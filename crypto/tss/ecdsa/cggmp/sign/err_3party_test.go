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
	"sync"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types/message"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	err3Once        sync.Once
	errPaillierKeyC *paillier.Paillier
	errPedZKC       *paillierzkproof.PederssenOpenParameter
)

func ensureErr3Paillier() {
	err3Once.Do(func() {
		var err error
		errPaillierKeyC, err = paillier.NewPaillier(2048)
		Expect(err).Should(BeNil())
		ped, err := errPaillierKeyC.NewPedersenParameterByPaillier()
		Expect(err).Should(BeNil())
		errPedZKC = paillierzkproof.NewPedersenOpenParameter(
			ped.PedersenOpenParameter.GetN(),
			ped.PedersenOpenParameter.GetS(),
			ped.PedersenOpenParameter.GetT(),
		)
	})
}

type err1ThreeParty struct {
	id     string
	k      *big.Int
	gamma  *big.Int
	rho    *big.Int
	mu     *big.Int
	K      *big.Int
	G      *big.Int
	Gamma  *pt.ECPoint
	delta  *big.Int
	bigD   *pt.ECPoint
	own    *peer
	peers  map[string]*peer
	paill  *paillier.Paillier
	pmIdx  int
}

var _ = Describe("HonestErr3Party", func() {
	It("Err1 cross-verify blamed==0 and tamper blames sender", func() {
		ensureErr3Paillier()

		ssid := []byte("3P-Err1")
		ID1, ID2, ID3 := tss.GetTestID(0), tss.GetTestID(1), tss.GetTestID(2)
		keys := []*paillier.Paillier{errPaillierKeyA, errPaillierKeyB, errPaillierKeyC}
		peds := []*paillierzkproof.PederssenOpenParameter{errPedZKA, errPedZKB, errPedZKC}
		ids := []string{ID1, ID2, ID3}
		ks := []*big.Int{big.NewInt(5), big.NewInt(2), big.NewInt(7)}
		gammas := []*big.Int{big.NewInt(11), big.NewInt(10), big.NewInt(3)}

		K := make([]*big.Int, 3)
		G := make([]*big.Int, 3)
		rho := make([]*big.Int, 3)
		mu := make([]*big.Int, 3)
		Gamma := make([]*pt.ECPoint, 3)
		for i := 0; i < 3; i++ {
			var err error
			K[i], rho[i], err = keys[i].EncryptWithOutputSalt(ks[i])
			Expect(err).Should(BeNil())
			G[i], mu[i], err = keys[i].EncryptWithOutputSalt(gammas[i])
			Expect(err).Should(BeNil())
			Gamma[i] = errTestG.ScalarMult(gammas[i])
		}

		sumGamma := errTestG.ScalarMult(gammas[0])
		var err error
		sumGamma, err = sumGamma.Add(Gamma[1])
		Expect(err).Should(BeNil())
		sumGamma, err = sumGamma.Add(Gamma[2])
		Expect(err).Should(BeNil())

		curveN := errTestPublicKey.GetCurve().Params().N

		// Directed MtA: mta[i][j] = party i toward party j (i?j).
		type mtaEdge struct {
			beta, r, count *big.Int
			dBytes, f      *big.Int
			psi            *paillierzkproof.PaillierAffAndGroupRangeMessage
			alpha          *big.Int
		}
		mta := make([][]*mtaEdge, 3)
		for i := 0; i < 3; i++ {
			mta[i] = make([]*mtaEdge, 3)
		}
		for i := 0; i < 3; i++ {
			for j := 0; j < 3; j++ {
				if i == j {
					continue
				}
				beta, count, r, _, dBytes, f, psi, e := cggmp.MtaWithProofAff_g(
					ssid, peds[j], keys[i], K[j].Bytes(), gammas[i], Gamma[i])
				Expect(e).Should(BeNil())
				alpha, e := keys[j].Decrypt(dBytes)
				Expect(e).Should(BeNil())
				mta[i][j] = &mtaEdge{
					beta: beta, count: count, r: r,
					dBytes: new(big.Int).SetBytes(dBytes), f: f, psi: psi,
					alpha: new(big.Int).SetBytes(alpha),
				}
			}
		}

		deltas := make([]*big.Int, 3)
		bigDeltas := make([]*pt.ECPoint, 3)
		for i := 0; i < 3; i++ {
			d := new(big.Int).Mul(ks[i], gammas[i])
			for j := 0; j < 3; j++ {
				if i == j {
					continue
				}
				// alpha from party j's MTA toward i (D_{j,i} under i's key)
				d.Add(d, mta[j][i].alpha)
				// beta from own MTA toward j
				d.Add(d, mta[i][j].beta)
			}
			d.Mod(d, curveN)
			deltas[i] = d
			bigDeltas[i] = sumGamma.ScalarMult(ks[i])
		}

		bks := []*birkhoffinterpolation.BkParameter{
			birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0),
			birkhoffinterpolation.NewBkParameter(big.NewInt(3), 0),
			birkhoffinterpolation.NewBkParameter(big.NewInt(5), 0),
		}

		parties := make([]*err1ThreeParty, 3)
		for i := 0; i < 3; i++ {
			own := newErrTestPeer(ids[i], ssid, peds[i])
			own.bk = bks[i]
			peers := make(map[string]*peer)
			for j := 0; j < 3; j++ {
				if i == j {
					continue
				}
				// View of peer j at party i:
				// round1: own MTA toward j (beta_ij, F_ij) + peer j's K/G
				// round2: peer j's MTA toward i (D_ji, alpha_ji, psi_ji)
				pj := &peer{
					Peer:       message.NewPeer(ids[j]),
					ssidWithBk: ssid,
					para:       peds[j],
					bk:         bks[j],
					round1Data: &round1Data{
						countDelta:      mta[i][j].count,
						kCiphertext:     K[j],
						gammaCiphertext: G[j],
						beta:            mta[i][j].beta,
						r:               mta[i][j].r,
						D:               mta[i][j].dBytes.Bytes(),
						F:               mta[i][j].f,
					},
					round2Data: &round2Data{
						d:             mta[j][i].dBytes,
						f:             mta[j][i].f,
						alpha:         mta[j][i].alpha,
						allGammaPoint: Gamma[j],
						psiProof:      mta[j][i].psi,
					},
					round3Data: &round3Data{delta: deltas[j]},
				}
				r3, e := bigDeltas[j].ToEcPointMessage()
				Expect(e).Should(BeNil())
				Expect(pj.AddMessage(&Message{
					Id: ids[j], Type: Type_Round3,
					Body: &Message_Round3{Round3: &Round3Msg{BigDelta: r3}},
				})).Should(Succeed())
				peers[ids[j]] = pj
			}
			parties[i] = &err1ThreeParty{
				id: ids[i], k: ks[i], gamma: gammas[i], rho: rho[i], mu: mu[i],
				K: K[i], G: G[i], Gamma: Gamma[i], delta: deltas[i], bigD: bigDeltas[i],
				own: own, peers: peers, paill: keys[i], pmIdx: i,
			}
		}

		handlers := make([]*round3Handler, 3)
		errMsgs := make([]*Message, 3)
		for i, party := range parties {
			h := newRound3HandlerErr1(party.k, party.gamma, party.rho, party.mu, party.K, party.G, party.delta, party.bigD, sumGamma, party.paill, party.peers, party.pmIdx, party.own)
			Expect(h.buildDeltaVerifyFailureMsg()).Should(Succeed())
			handlers[i] = h
			errMsgs[i] = &Message{Id: party.id, Type: Type_Err1, Body: h.err1Msg.Body}
		}

		// Each party verifies the other two honest Err1 messages.
		for i, h := range handlers {
			others := make([]*Message, 0, 2)
			for j, m := range errMsgs {
				if i != j {
					others = append(others, m)
				}
			}
			blamed, e := h.ProcessErr1Msg(others)
			Expect(e).Should(BeNil())
			Expect(len(blamed.Union())).Should(BeZero())
		}

		// Tamper party2's C toward party1 -> party1 blames party2.
		tampered := &Message{Id: ID2, Type: Type_Err1, Body: handlers[1].err1Msg.Body}
		peerMsg := tampered.GetErr1().Peers[ID1]
		Expect(peerMsg).ShouldNot(BeNil())
		Expect(len(peerMsg.ProductCiphertext)).Should(BeNumerically(">", 0))
		peerMsg.ProductCiphertext[0] ^= 0xff
		blamed, e := handlers[0].ProcessErr1Msg([]*Message{tampered, errMsgs[2]})
		Expect(e).Should(BeNil())
		Expect(blamed.Union()).To(HaveKey(ID2))
	})
})
