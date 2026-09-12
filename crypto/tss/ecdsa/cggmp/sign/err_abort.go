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

	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
)

func (p *round3Handler) blamePeer(id string) {
	if p.onBlamedPeers != nil {
		p.onBlamedPeers(map[string]struct{}{id: {}})
	}
}

func (p *round3Handler) publishErr1() {
	if p.err1Msg == nil {
		return
	}
	if p.onAbortMsg != nil {
		p.onAbortMsg(p.err1Msg)
	}
	cggmp.Broadcast(p.peerManager, p.err1Msg)
}

func (p *round3Handler) ensureErr1Built() error {
	if p.err1Msg != nil {
		return nil
	}
	return p.buildDeltaVerifyFailureMsg()
}

func (p *round4Handler) publishErr2() {
	if p.err2Msg == nil {
		return
	}
	if p.onAbortMsg != nil {
		p.onAbortMsg(p.err2Msg)
	}
	cggmp.Broadcast(p.peerManager, p.err2Msg)
}

func (p *round4Handler) ensureErr2Built() error {
	if p.err2Msg != nil {
		return nil
	}
	return p.buildSigmaVerifyFailureMsg()
}

func peerPaillierNs(peers map[string]*peer) map[string]*big.Int {
	out := make(map[string]*big.Int, len(peers))
	for id, peer := range peers {
		out[id] = peer.para.GetN()
	}
	return out
}

func peerBetaCounts(peers map[string]*peer, useSigma bool) map[string]*big.Int {
	out := make(map[string]*big.Int, len(peers))
	for id, peer := range peers {
		var c *big.Int
		if peer.round1Data != nil {
			if useSigma {
				c = peer.round1Data.countSigma
			} else {
				c = peer.round1Data.countDelta
			}
		}
		if c == nil {
			c = big.NewInt(0)
		}
		out[id] = c
	}
	return out
}

// decModQWitness decrypts untranslated product C and lifts Y=yEnc+kN so
// Enc(Y)=C and Y≡x (mod q) with small k (Scheme A').
func decModQWitness(key *paillier.Paillier, C, x, q *big.Int) (y, salt *big.Int, err error) {
	yEncBytes, err := key.Decrypt(C.Bytes())
	if err != nil {
		return nil, nil, err
	}
	y, err = cggmp.LiftDecryptToModQBounded(new(big.Int).SetBytes(yEncBytes), key.GetN(), x, q)
	if err != nil {
		return nil, nil, err
	}
	nthRoot, err := key.GetNthRoot()
	if err != nil {
		return nil, nil, err
	}
	salt = cggmp.DeriveProductEncSalt(key.GetN(), key.GetNSquare(), nthRoot, y, C)
	return y, salt, nil
}

func newPeerDecModQProof(
	ssid []byte,
	y, salt, n, C, proofX *big.Int,
	ped *paillierzkproof.PederssenOpenParameter,
) (*paillierzkproof.DecModQMessage, error) {
	return paillierzkproof.NewDecModQMessage(
		paillierzkproof.NewS256(), ssid, y, salt, n, C, proofX, ped,
	)
}

func buildErr1PeerMsgs(
	p *round3Handler,
	plaintextY, salt, finalC, proofX *big.Int,
) (map[string]*Err1PeerMsg, error) {
	peersMsg := make(map[string]*Err1PeerMsg, len(p.peers))
	finalBytes := cloneBytes(finalC.Bytes())
	for _, peer := range p.peers {
		proofDec, err := newPeerDecModQProof(
			p.own.ssidWithBk, plaintextY, salt, p.paillierKey.GetN(), finalC, proofX, peer.para,
		)
		if err != nil {
			return nil, err
		}
		peersMsg[peer.Id] = &Err1PeerMsg{
			DecModQ:           proofDec,
			ProductCiphertext: cloneBytes(finalBytes),
			D:                 cloneBytes(peer.round2Data.d.Bytes()),
			F:                 cloneBytes(peer.round1Data.F.Bytes()),
		}
	}
	return peersMsg, nil
}

func attachErr2DecModQ(
	p *round4Handler,
	plaintextY, salt, finalC, proofX *big.Int,
	peersMsg map[string]*Err2PeerMsg,
) error {
	finalBytes := cloneBytes(finalC.Bytes())
	for _, peer := range p.peers {
		entry := peersMsg[peer.Id]
		if entry == nil {
			continue
		}
		proof, err := newPeerDecModQProof(
			p.own.ssidWithBk, plaintextY, salt, p.paillierKey.GetN(), finalC, proofX, peer.para,
		)
		if err != nil {
			return err
		}
		entry.DecModQ = proof
		entry.ProductCiphertext = cloneBytes(finalBytes)
		entry.D = cloneBytes(peer.round2Data.dhat.Bytes())
		entry.F = cloneBytes(peer.round1Data.Fhat.Bytes())
	}
	return nil
}

func attachErr2DecModQKm(
	p *round4Handler,
	plaintextY, salt, km, proofX *big.Int,
	peersMsg map[string]*Err2PeerMsg,
) error {
	for _, peer := range p.peers {
		entry := peersMsg[peer.Id]
		if entry == nil {
			continue
		}
		proof, err := newPeerDecModQProof(
			p.own.ssidWithBk, plaintextY, salt, p.paillierKey.GetN(), km, proofX, peer.para,
		)
		if err != nil {
			return err
		}
		entry.DecModQKm = proof
	}
	return nil
}
