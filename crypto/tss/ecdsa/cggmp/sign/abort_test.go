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

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Echo message", func() {
	It("GetEchoMessage skips Round1 reveal (bound by Round1Digest)", func() {
		m := &Message{
			Type: Type_Round1,
			Id:   "peer-1",
			Body: &Message_Round1{
				Round1: &Round1Msg{
					KCiphertext:     []byte("k"),
					GammaCiphertext: []byte("g"),
				},
			},
		}
		Expect(m.GetEchoMessage()).To(BeNil())
	})

	It("GetEchoMessage returns Round1Digest for commit echo", func() {
		m := &Message{
			Type: Type_Round1Digest,
			Id:   "peer-1",
			Body: &Message_Round1Digest{
				Round1Digest: &Round1DigestMsg{
					KCiphertext:     []byte("k"),
					GammaCiphertext: []byte("g"),
					ToPeer:          []*PeerDigestEntry{{PeerId: "peer-2", Digest: make([]byte, 32)}},
					TableRoot:       make([]byte, 32),
				},
			},
		}
		echo := m.GetEchoMessage()
		Expect(echo).NotTo(BeNil())
		Expect(echo.(*Message).GetRound1Digest().GetKCiphertext()).To(Equal([]byte("k")))
	})

	It("GetEchoMessage returns Err1/Err2 payloads for abort echo", func() {
		err1 := &Message{
			Type: Type_Err1,
			Id:   "peer-1",
			Body: &Message_Err1{Err1: &Err1Msg{
				KgammaCiphertext: []byte("kg"),
				Peers: map[string]*Err1PeerMsg{
					"peer-2": {ProductCiphertext: []byte("c2"), D: []byte("d2"), F: []byte("f2")},
				},
			}},
		}
		echo1 := err1.GetEchoMessage()
		Expect(echo1).NotTo(BeNil())
		Expect(echo1.(*Message).GetErr1().GetKgammaCiphertext()).To(Equal([]byte("kg")))
		Expect(echo1.(*Message).GetErr1().Peers).To(HaveKey("peer-2"))
		echoPeer := echo1.(*Message).GetErr1().Peers["peer-2"]
		Expect(echoPeer.GetD()).To(Equal([]byte("d2")))
		err1.GetErr1().Peers["peer-2"].D[0] ^= 0xff
		Expect(echoPeer.GetD()).To(Equal([]byte("d2")))

		err2 := &Message{
			Type: Type_Err2,
			Id:   "peer-1",
			Body: &Message_Err2{Err2: &Err2Msg{
				KMulBkShareCiphertext: []byte("kb"),
				Chi:                   []byte("chi"),
				Peers: map[string]*Err2PeerMsg{
					"peer-2": {ProductCiphertext: []byte("c2"), D: []byte("d2"), F: []byte("f2")},
				},
			}},
		}
		echo2 := err2.GetEchoMessage()
		Expect(echo2).NotTo(BeNil())
		Expect(echo2.(*Message).GetErr2().GetKMulBkShareCiphertext()).To(Equal([]byte("kb")))
		Expect(echo2.(*Message).GetErr2().GetChi()).To(Equal([]byte("chi")))
		err2.GetErr2().Chi[0] ^= 0xff
		Expect(echo2.(*Message).GetErr2().GetChi()).To(Equal([]byte("chi")))
	})

	It("GetEchoMessage skips Round2/Round3/Round4 reveal; echoes digests only", func() {
		r2 := &Message{
			Type: Type_Round2,
			Id:   "peer-1",
			Body: &Message_Round2{
				Round2: &Round2Msg{
					Gamma: &ecpointgrouplaw.EcPointMessage{Curve: 1, X: []byte("x"), Y: []byte("y")},
				},
			},
		}
		Expect(r2.GetEchoMessage()).To(BeNil())

		r2d := &Message{
			Type: Type_Round2Digest,
			Id:   "peer-1",
			Body: &Message_Round2Digest{
				Round2Digest: &Round2DigestMsg{
					Gamma:     &ecpointgrouplaw.EcPointMessage{Curve: 1, X: []byte("x"), Y: []byte("y")},
					TableRoot: make([]byte, 32),
				},
			},
		}
		echo2d := r2d.GetEchoMessage()
		Expect(echo2d).NotTo(BeNil())
		Expect(echo2d.(*Message).GetRound2Digest().GetGamma().GetX()).To(Equal([]byte("x")))

		r3 := &Message{
			Type: Type_Round3,
			Id:   "peer-1",
			Body: &Message_Round3{
				Round3: &Round3Msg{
					Delta:    "42",
					BigDelta: &ecpointgrouplaw.EcPointMessage{Curve: 1, X: []byte("dx"), Y: []byte("dy")},
				},
			},
		}
		Expect(r3.GetEchoMessage()).To(BeNil())

		r3d := &Message{
			Type: Type_Round3Digest,
			Id:   "peer-1",
			Body: &Message_Round3Digest{
				Round3Digest: &Round3DigestMsg{
					Delta:     "42",
					BigDelta:  &ecpointgrouplaw.EcPointMessage{Curve: 1, X: []byte("dx"), Y: []byte("dy")},
					TableRoot: make([]byte, 32),
				},
			},
		}
		echo3d := r3d.GetEchoMessage()
		Expect(echo3d).NotTo(BeNil())
		Expect(echo3d.(*Message).GetRound3Digest().GetDelta()).To(Equal("42"))

		r4 := &Message{
			Type: Type_Round4,
			Id:   "peer-1",
			Body: &Message_Round4{
				Round4: &Round4Msg{Sigmai: []byte("sig")},
			},
		}
		echo4 := r4.GetEchoMessage()
		Expect(echo4).To(BeNil())
	})
})

var _ = Describe("GetBlamedPeers fallback", func() {
	It("returns empty map when abort snapshot is empty", func() {
		sign := &Sign{
			abortCollector: cggmp.NewAbortMsgCollector[*Message](),
			MessageMain:    &stubMessageMain{state: types.StateFailed, handler: &round4Handler{}},
		}
		blamed, err := sign.GetBlamedPeers()
		Expect(err).Should(BeNil())
		Expect(blamed).To(BeEmpty())
	})

	It("falls back to round4Handler ProcessErr2Msg", func() {
		ssidInfoWithBK := []byte("fallback-err2")
		k1 := big.NewInt(5)
		k2 := big.NewInt(2)
		K1, rho1, err := errPaillierKeyA.EncryptWithOutputSalt(k1)
		Expect(err).Should(BeNil())
		K2, rho2, err := errPaillierKeyB.EncryptWithOutputSalt(k2)
		Expect(err).Should(BeNil())
		b1 := big.NewInt(3)
		b2 := big.NewInt(10)
		x1 := big.NewInt(2)
		x2 := big.NewInt(3)
		bk1 := big.NewInt(2)
		bk2 := big.NewInt(-1)
		rX := big.NewInt(17)
		R := errTestG.ScalarMult(rX)
		ID1 := tss.GetTestID(0)
		ID2 := tss.GetTestID(1)
		bkMulShare1 := new(big.Int).Mul(x1, bk1)
		bkMulShare2 := new(big.Int).Mul(x2, bk2)
		bkPartial1 := errTestG.ScalarMult(x1).ScalarMult(bk1)
		bkPartial2 := errTestG.ScalarMult(x2).ScalarMult(bk2)

		p1Setup, p2Setup := setupErr2Parties(ssidInfoWithBK, errPaillierKeyA, errPaillierKeyB, K1, K2, k1, k2, x1, x2, bkMulShare1, bkMulShare2, bkPartial1, bkPartial2, rX, ID1, ID2)
		p4 := newRound4HandlerErr2(b1, k1, rho1, rX, K1, errPaillierKeyA, map[string]*peer{ID2: p1Setup.peer}, 0, p1Setup.own)
		p2Err := newRound4HandlerErr2(b2, k2, rho2, rX, K2, errPaillierKeyB, map[string]*peer{ID1: p2Setup.peer}, 1, p2Setup.own)
		p4.R = R
		p2Err.R = R
		p4.chi = p1Setup.chi
		p2Err.chi = p2Setup.chi
		p4.sigma = p1Setup.sigma
		p2Err.sigma = p2Setup.sigma
		p4.bkMulShare = bkMulShare1
		p2Err.bkMulShare = bkMulShare2
		p4.bkpartialPubKey = bkPartial1
		p2Err.bkpartialPubKey = bkPartial2
		Expect(p2Err.buildSigmaVerifyFailureMsg()).Should(Succeed())

		collector := cggmp.NewAbortMsgCollector[*Message]()
		collector.Record(&Message{Id: ID2, Type: Type_Err2, Body: p2Err.err2Msg.Body})
		sign := &Sign{
			abortCollector: collector,
			MessageMain:    &stubMessageMain{state: types.StateFailed, handler: p4},
		}
		blamed, err := sign.GetBlamedPeers()
		Expect(err).Should(BeNil())
		Expect(blamed).To(BeEmpty())
	})

	It("falls back to round3Handler ProcessErr1Msg", func() {
		ssidInfoWithBK := []byte("fallback-err1")
		k1 := big.NewInt(5)
		k2 := big.NewInt(2)
		K1, rho1, err := errPaillierKeyA.EncryptWithOutputSalt(k1)
		Expect(err).Should(BeNil())
		K2, rho2, err := errPaillierKeyB.EncryptWithOutputSalt(k2)
		Expect(err).Should(BeNil())
		gamma1 := big.NewInt(11)
		gamma2 := big.NewInt(10)
		G1, mu1, err := errPaillierKeyA.EncryptWithOutputSalt(gamma1)
		Expect(err).Should(BeNil())
		G2, mu2, err := errPaillierKeyB.EncryptWithOutputSalt(gamma2)
		Expect(err).Should(BeNil())
		Gamma1 := errTestG.ScalarMult(gamma1)
		Gamma2 := errTestG.ScalarMult(gamma2)
		sumGamma := errTestG.ScalarMult(gamma1)
		sumGamma, err = sumGamma.Add(Gamma2)
		Expect(err).Should(BeNil())
		bigDelta1 := sumGamma.ScalarMult(k1)
		bigDelta2 := sumGamma.ScalarMult(k2)
		ID1 := tss.GetTestID(0)
		ID2 := tss.GetTestID(1)

		p1Setup, p2Setup := setupErr1Parties(ssidInfoWithBK, errPaillierKeyA, errPaillierKeyB, k1, k2, K1, K2, G1, G2, gamma1, gamma2, Gamma1, Gamma2, bigDelta1, bigDelta2, ID1, ID2)
		p3 := newRound3HandlerErr1(k1, gamma1, rho1, mu1, K1, G1, p1Setup.delta, bigDelta1, sumGamma, errPaillierKeyA, map[string]*peer{ID2: p1Setup.peer}, 0, p1Setup.own)
		p2Err := newRound3HandlerErr1(k2, gamma2, rho2, mu2, K2, G2, p2Setup.delta, bigDelta2, sumGamma, errPaillierKeyB, map[string]*peer{ID1: p2Setup.peer}, 1, p2Setup.own)
		Expect(p2Err.buildDeltaVerifyFailureMsg()).Should(Succeed())

		collector := cggmp.NewAbortMsgCollector[*Message]()
		collector.Record(&Message{Id: ID2, Type: Type_Err1, Body: p2Err.err1Msg.Body})
		sign := &Sign{
			abortCollector: collector,
			MessageMain:    &stubMessageMain{state: types.StateFailed, handler: p3},
		}
		blamed, err := sign.GetBlamedPeers()
		Expect(err).Should(BeNil())
		Expect(blamed).To(BeEmpty())
	})
})
