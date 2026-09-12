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
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type round3Data struct {
	delta *big.Int
}

type round3Handler struct {
	*round2Handler

	sigma *big.Int
	R     *pt.ECPoint

	// Error analysis
	err1Msg *Message
}

func newRound3Handler(round2Handler *round2Handler) (*round3Handler, error) {
	return &round3Handler{
		round2Handler: round2Handler,
	}, nil
}

func (p *round3Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Round3)
}

func (p *round3Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum
}

func (p *round3Handler) IsHandled(logger log.Logger, id string) bool {
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return false
	}
	return peer.Messages[p.MessageType()] != nil
}

func (p *round3Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		logger.Warn("Peer not found")
		return tss.ErrPeerNotFound
	}
	round3 := msg.GetRound3()
	// Compute r=R|x-axis and σi =km+rχ.
	ownPed := p.own.para
	Delta, err := round3.BigDelta.ToPoint()
	if err != nil {
		logger.Debug("Failed to ToPoint", "err", err)
		return err
	}
	err = round3.Psidoublepai.Verify(parameter, peer.ssidWithBk, peer.round1Data.kCiphertext, peer.para.GetN(), ownPed, Delta, p.sumGamma)
	if err != nil {
		logger.Debug("Failed to Verify", "err", err)
		return err
	}

	tempDelta, err := cggmp.ParseBigIntString(round3.Delta, 10)
	if err != nil {
		logger.Debug("Failed to parse delta", "err", err)
		return err
	}
	peer.round3Data = &round3Data{
		delta: tempDelta,
	}

	return peer.AddMessage(msg)
}

func (p *round3Handler) Finalize(logger log.Logger) (types.Handler, error) {
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N
	delta := new(big.Int).Set(p.delta)
	bigDelta := p.BigDelta.Copy()
	for _, peer := range p.peers {
		round3 := getMessage(peer.GetMessage(types.MessageType(Type_Round3))).GetRound3()
		Delta, err := round3.BigDelta.ToPoint()
		if err != nil {
			logger.Debug("Failed to ToPoint", "err", err)
			return nil, err
		}

		delta.Add(delta, peer.round3Data.delta)
		bigDelta, err = bigDelta.Add(Delta)
		if err != nil {
			logger.Debug("Failed to Add", "err", err)
			return nil, err
		}
	}

	// Do verification
	gDelta := pt.NewBase(curve).ScalarMult(delta)
	if !gDelta.Equal(bigDelta) {
		return p.enterErr1Phase(logger, ErrInvalidDelta)
	}
	R := p.sumGamma.ScalarMult(new(big.Int).ModInverse(delta, curveN))
	if R.IsIdentity() {
		logger.Debug("Identity point")
		return nil, ErrZeroR
	}
	r := R.GetX()
	// Recall that msg := Hash(message)
	sigma := new(big.Int).Mul(p.k, new(big.Int).SetBytes(p.msg))

	sigma.Add(sigma, new(big.Int).Mul(r, p.chi))
	sigma.Mod(sigma, curveN)

	p.sigma = sigma
	p.R = R
	cggmp.Broadcast(p.peerManager, &Message{
		Id:   p.peerManager.SelfID(),
		Type: Type_Round4,
		Body: &Message_Round4{
			Round4: &Round4Msg{
				Sigmai: sigma.Bytes(),
			},
		},
	})
	return newRound4Handler(p)
}

func (p *round3Handler) buildDeltaVerifyFailureMsg() error {
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N
	p.delta = new(big.Int).Mod(p.delta, curveN)
	for _, peer := range p.peers {
		ownPed := p.own.para
		n := peer.para.GetN()
		// Verify psi
		err := peer.round2Data.psiProof.Verify(paillier.NewS256(), peer.ssidWithBk, p.paillierKey.GetN(), n, p.kCiphertext, peer.round2Data.d, peer.round2Data.f, ownPed, peer.round2Data.allGammaPoint)
		if err != nil {
			p.blamePeer(peer.Id)
			return err
		}
	}
	// B: Compute Hi = enci(ki · γi) and prove in ZK that Hi is well formed wrt Ki and Gi in Πmul.
	kMulGamma := new(big.Int).Mul(p.gamma, p.k)
	kMulGammaCiphertext, randomRho, err := p.paillierKey.EncryptWithOutputSalt(kMulGamma)
	if err != nil {
		return err
	}
	rho := new(big.Int).Exp(p.mu, new(big.Int).Neg(p.k), p.paillierKey.GetNSquare())
	rho.Mul(rho, randomRho)
	rho.Mod(rho, p.paillierKey.GetNSquare())
	proofMul, err := paillier.NewMulMessage(p.own.ssidWithBk, p.k, rho, p.rho, p.paillierKey.GetN(), p.kCiphertext, p.gammaCiphertext, kMulGammaCiphertext, curveN)
	if err != nil {
		return err
	}

	deltaCiphertext := new(big.Int).Set(kMulGammaCiphertext)
	nSquare := p.paillierKey.GetNSquare()

	for _, peer := range p.peers {
		deltaCiphertext.Mul(peer.round2Data.d, deltaCiphertext)
		deltaCiphertext.Mul(new(big.Int).ModInverse(peer.round1Data.F, nSquare), deltaCiphertext)
		deltaCiphertext.Mod(deltaCiphertext, nSquare)
	}

	// Scheme A': prove DecModQ on untranslated C0 with x=(δ+Σc·N) mod q.
	finalC := deltaCiphertext
	proofX := cggmp.DecModQPublicX(p.delta, curveN, peerPaillierNs(p.peers), peerBetaCounts(p.peers, false))
	y, salt, err := decModQWitness(p.paillierKey, finalC, proofX, curveN)
	if err != nil {
		return err
	}

	peersMsg, err := buildErr1PeerMsgs(p, y, salt, finalC, proofX)
	if err != nil {
		return err
	}

	p.err1Msg = &Message{
		Id:   p.peerManager.SelfID(),
		Type: Type_Err1,
		Body: &Message_Err1{
			Err1: &Err1Msg{
				KgammaCiphertext: kMulGammaCiphertext.Bytes(),
				MulProof:         proofMul,
				Peers:            peersMsg,
			},
		},
	}
	return nil
}
