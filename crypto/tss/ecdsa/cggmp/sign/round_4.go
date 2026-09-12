// Copyright © 2022 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sign

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/utils"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	// ErrZeroS is returned if the s is zero
	ErrZeroS = errors.New("zero s")

	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
)

type round4Data struct {
	sigma *big.Int
	// chi is the MtA share used to form σ=k·m+r·χ; required for Scheme A' Err2 verify.
	chi *big.Int
}

type round4Handler struct {
	*round3Handler

	result *Result

	err2Msg *Message
}

func newRound4Handler(round3Handler *round3Handler) (*round4Handler, error) {
	return &round4Handler{
		round3Handler: round3Handler,
	}, nil
}

func (p *round4Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round4)
}

func (p *round4Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round4Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round4Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}

	round4 := msg.GetRound4()
	peer.round4Data = &round4Data{
		sigma: new(big.Int).SetBytes(round4.Sigmai),
	}
	return peer.AddMessage(msg)
}

func (p *round4Handler) Finalize(logger log.Logger) (types.Handler, error) {
	curveN := p.pubKey.GetCurve().Params().N
	// Set σ=sum_j σj.
	s := new(big.Int).Set(p.sigma)
	for _, peer := range p.peers {
		s.Add(s, peer.round4Data.sigma)
	}
	s.Mod(s, curveN)
	if s.Cmp(big0) == 0 {
		return nil, ErrZeroS
	}

	// Verify that (r,s) is a correct signature
	isCorrectSig := ecdsa.Verify(p.pubKey.ToPubKey(), p.msg, p.R.GetX(), s)
	if !isCorrectSig {
		return p.enterErr2Phase(logger, ErrIncorrectSig)
	}
	p.result = &Result{
		R: p.R.GetX(),
		S: s,
	}
	return nil, nil
}

func (p *round4Handler) buildSigmaVerifyFailureMsg() error {
	curveN := p.pubKey.GetCurve().Params().N
	p.sigma = new(big.Int).Mod(p.sigma, curveN)
	// A: Reprove that {Dhatj,i}j ̸=i are well-formed according to prod_ell^aff-g , for l ̸= j,i.
	for _, peer := range p.peers {
		ownPed := p.own.para
		n := peer.para.GetN()
		// Verify psi
		bkPartialKey := peer.partialPubKey.ScalarMult(peer.bkcoefficient)
		err := peer.round2Data.psihatProoof.Verify(paillierzkproof.NewS256(), peer.ssidWithBk, p.paillierKey.GetN(), n, p.kCiphertext, peer.round2Data.dhat, peer.round2Data.fhat, ownPed, bkPartialKey)
		if err != nil {
			p.round3Handler.blamePeer(peer.Id)
			return err
		}
	}
	// B: Compute Hˆi = enci(ki · xi) and prove in ZK that Hˆi is well-formed wrt Ki and Xi according to Πmul∗, for l ̸= i.
	rho, err := utils.RandomCoprimeInt(p.paillierKey.GetNSquare())
	if err != nil {
		return err
	}
	nSquare := p.paillierKey.GetNSquare()
	dciphertext := new(big.Int).Exp(p.kCiphertext, p.bkMulShare, nSquare)
	dciphertext.Mul(dciphertext, new(big.Int).Exp(rho, p.paillierKey.GetN(), nSquare))
	dciphertext.Mod(dciphertext, nSquare)

	innerProductCiphertext := new(big.Int).Set(dciphertext)

	// Compute MulStarProof
	peersMsg := make(map[string]*Err2PeerMsg, len(p.peers))
	for _, peer := range p.peers {
		ped := peer.para
		proofMulStar, err := paillierzkproof.NewMulStarMessage(paillierzkproof.NewS256(), p.own.ssidWithBk, p.bkMulShare, rho, p.paillierKey.GetN(), p.kCiphertext, dciphertext, ped, p.bkpartialPubKey)
		if err != nil {
			return err
		}
		entry := &Err2PeerMsg{
			MulStarProof: proofMulStar,
		}
		peersMsg[peer.Id] = entry

		// D̂_{j,i} under our Paillier; F̂_{i,j} is our enc(β̂) toward peer.
		innerProductCiphertext.Mul(peer.round2Data.dhat, innerProductCiphertext)
		innerProductCiphertext.Mul(new(big.Int).ModInverse(peer.round1Data.Fhat, nSquare), innerProductCiphertext)
		innerProductCiphertext.Mod(innerProductCiphertext, nSquare)
	}

	// Err2 Scheme A′: do NOT prove DecModQ on K^m·C_inner^r. That ciphertext decrypts to
	// k·m + r·(MtA inner product) with r·S ≫ N, so |Y|<8N bounded lift fails (Completeness)
	// and unbounded lift restores vacuous CRT (Soundness). Split instead:
	//   (1) DecModQ(C_inner, PublicX(χ))  — binds MtA inner layer to broadcast χ
	//   (2) DecModQ(K^m, σ−r·χ mod q)   — binds Round4 σ share via σ ≡ r·χ + (σ−r·χ)
	// Verify recomposes σ ≡ k·m + r·χ (mod q) using local R and Round4 σ.
	if p.chi == nil {
		return errors.New("missing chi for err2 dec-mod-q")
	}
	if p.msg == nil || p.R == nil {
		return errors.New("missing msg/R for err2 dec-mod-q")
	}
	p.chi = new(big.Int).Mod(p.chi, curveN)
	finalC := innerProductCiphertext
	proofX := cggmp.DecModQPublicX(p.chi, curveN, peerPaillierNs(p.peers), peerBetaCounts(p.peers, true))
	y, salt, err := decModQWitness(p.paillierKey, finalC, proofX, curveN)
	if err != nil {
		return err
	}
	if err := attachErr2DecModQ(p, y, salt, finalC, proofX, peersMsg); err != nil {
		return err
	}

	km := new(big.Int).Exp(p.kCiphertext, new(big.Int).SetBytes(p.msg), nSquare)
	xKm := new(big.Int).Mul(p.R.GetX(), p.chi)
	xKm.Sub(p.sigma, xKm)
	xKm.Mod(xKm, curveN)
	yKm, saltKm, err := decModQWitness(p.paillierKey, km, xKm, curveN)
	if err != nil {
		return err
	}
	if err := attachErr2DecModQKm(p, yKm, saltKm, km, xKm, peersMsg); err != nil {
		return err
	}

	chiBytes := make([]byte, (curveN.BitLen()+7)/8)
	p.chi.FillBytes(chiBytes)

	p.err2Msg = &Message{
		Id:   p.peerManager.SelfID(),
		Type: Type_Err2,
		Body: &Message_Err2{
			Err2: &Err2Msg{
				KMulBkShareCiphertext: dciphertext.Bytes(),
				Peers:                 peersMsg,
				Chi:                   chiBytes,
			},
		},
	}
	return nil
}
