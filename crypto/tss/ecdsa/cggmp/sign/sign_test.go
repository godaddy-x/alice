// Copyright © 2022 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package sign

import (
	"math/big"
	"testing"
	"time"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

func TestSign3Round(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sign Suite")
}

var _ = Describe("Refresh", func() {
	It("should be ok", func() {
		signs, _, listeners := newSigns()
		startAllAndWaitDone(signs, listeners)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
		assertMatchingSignResults(signs, 2)
	})

	It("digest timeout blames peer that never sends Round1Digest", func() {
		signs, _, listeners := newSigns()
		id0 := tss.GetTestID(0)
		id1 := tss.GetTestID(1)
		signs[id0].SetAbortTimeout(200 * time.Millisecond)

		done := make(chan struct{})
		listeners[id0].On("OnStateChanged", types.StateInit, types.StateFailed).Run(func(_ mock.Arguments) {
			close(done)
		}).Once()

		signs[id0].Start()
		Eventually(done, 2*time.Second).Should(BeClosed())

		blamed, err := signs[id0].GetBlamedPeers()
		Expect(err).Should(BeNil())
		Expect(blamed).To(HaveKey(id1))
	})

	It("Round2 digest timeout blames peer that never sends Round2Digest", func() {
		signs, _, listeners := buildSignsOpts(2, signBuildOptions{
			blockSendType: map[int]Type{1: Type_Round2Digest},
		})
		id0 := tss.GetTestID(0)
		id1 := tss.GetTestID(1)
		signs[id0].SetAbortTimeout(3 * time.Second)

		failed := make(chan struct{})
		listeners[id0].On("OnStateChanged", types.StateInit, types.StateFailed).Run(func(_ mock.Arguments) {
			close(failed)
		}).Once()

		for _, s := range signs {
			s.Start()
		}
		Eventually(failed, 10*time.Second).Should(BeClosed())

		blamed, err := signs[id0].GetBlamedPeers()
		Expect(err).Should(BeNil())
		Expect(blamed).To(HaveKey(id1))
	})

	It("Round3 digest timeout blames peer that never sends Round3Digest", func() {
		signs, _, listeners := buildSignsOpts(2, signBuildOptions{
			blockSendType: map[int]Type{1: Type_Round3Digest},
		})
		id0 := tss.GetTestID(0)
		id1 := tss.GetTestID(1)
		signs[id0].SetAbortTimeout(3 * time.Second)

		failed := make(chan struct{})
		listeners[id0].On("OnStateChanged", types.StateInit, types.StateFailed).Run(func(_ mock.Arguments) {
			close(failed)
		}).Once()

		for _, s := range signs {
			s.Start()
		}
		Eventually(failed, 15*time.Second).Should(BeClosed())

		blamed, err := signs[id0].GetBlamedPeers()
		Expect(err).Should(BeNil())
		Expect(blamed).To(HaveKey(id1))
	})

	It("ProcessErr1 rejects peer when Round2 digest mismatches store", func() {
		ssidInfoWithBK := []byte("digest-bind")
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
		map1 := map[string]*peer{ID2: p1Setup.peer}
		p1Err := newRound3HandlerErr1(k1, gamma1, rho1, mu1, K1, G1, p1Setup.delta, bigDelta1, sumGamma, errPaillierKeyA, map1, 0, p1Setup.own)
		p2Err := newRound3HandlerErr1(k2, gamma2, rho2, mu2, K2, G2, p2Setup.delta, bigDelta2, sumGamma, errPaillierKeyB, map[string]*peer{ID1: p2Setup.peer}, 1, p2Setup.own)
		Expect(p1Err.buildDeltaVerifyFailureMsg()).Should(Succeed())
		Expect(p2Err.buildDeltaVerifyFailureMsg()).Should(Succeed())

		r2Body := &Round2Msg{
			D:  p1Setup.peer.round2Data.d.Bytes(),
			F:  p1Setup.peer.round2Data.f.Bytes(),
			Psi: p1Setup.peer.round2Data.psiProof,
		}
		Expect(p1Setup.peer.AddMessage(&Message{
			Id: ID2, Type: Type_Round2, Body: &Message_Round2{Round2: r2Body},
		})).Should(Succeed())

		store := newPairwiseDigestStore()
		wrong, err := Round2PairwiseDigest(ssidInfoWithBK, ID2, ID1, &Round2Msg{D: []byte{0xff}})
		Expect(err).Should(BeNil())
		store.SetFinalized(digestR2, ID2, map[string][]byte{ID1: wrong})
		p1Err.digestStore = store
		p1Err.ssid = ssidInfoWithBK

		errMsg2 := &Message{Id: ID2, Type: Type_Err1, Body: p2Err.err1Msg.Body}
		blamed, err := p1Err.ProcessErr1Msg([]*Message{errMsg2})
		Expect(err).Should(BeNil())
		Expect(blamed).To(HaveKey(ID2))
	})

	It("ProcessErr2 rejects peer when Round2 digest mismatches store", func() {
		ssidInfoWithBK := []byte("digest-bind-err2")
		k1 := big.NewInt(5)
		k2 := big.NewInt(2)
		b1 := big.NewInt(3)
		b2 := big.NewInt(10)
		K1, rho1, err := errPaillierKeyA.EncryptWithOutputSalt(k1)
		Expect(err).Should(BeNil())
		K2, rho2, err := errPaillierKeyB.EncryptWithOutputSalt(k2)
		Expect(err).Should(BeNil())
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
		map1 := map[string]*peer{ID2: p1Setup.peer}
		p1Err := newRound4HandlerErr2(b1, k1, rho1, rX, K1, errPaillierKeyA, map1, 0, p1Setup.own)
		p2Err := newRound4HandlerErr2(b2, k2, rho2, rX, K2, errPaillierKeyB, map[string]*peer{ID1: p2Setup.peer}, 1, p2Setup.own)
		p1Err.R = R
		p2Err.R = R
		p1Err.chi = p1Setup.chi
		p2Err.chi = p2Setup.chi
		p1Err.sigma = p1Setup.sigma
		p2Err.sigma = p2Setup.sigma
		p1Err.bkMulShare = bkMulShare1
		p2Err.bkMulShare = bkMulShare2
		p1Err.bkpartialPubKey = bkPartial1
		p2Err.bkpartialPubKey = bkPartial2
		Expect(p1Err.buildSigmaVerifyFailureMsg()).Should(Succeed())
		Expect(p2Err.buildSigmaVerifyFailureMsg()).Should(Succeed())

		r2Body := &Round2Msg{
			Dhat:   p1Setup.peer.round2Data.dhat.Bytes(),
			Fhat:   p1Setup.peer.round2Data.fhat.Bytes(),
			Psihat: p1Setup.peer.round2Data.psihatProoof,
		}
		Expect(p1Setup.peer.AddMessage(&Message{
			Id: ID2, Type: Type_Round2, Body: &Message_Round2{Round2: r2Body},
		})).Should(Succeed())

		store := newPairwiseDigestStore()
		wrong, err := Round2PairwiseDigest(ssidInfoWithBK, ID2, ID1, &Round2Msg{Dhat: []byte{0xff}})
		Expect(err).Should(BeNil())
		store.SetFinalized(digestR2, ID2, map[string][]byte{ID1: wrong})
		p1Err.digestStore = store
		p1Err.ssid = ssidInfoWithBK

		errMsg2 := &Message{Id: ID2, Type: Type_Err2, Body: p2Err.err2Msg.Body}
		blamed, err := p1Err.ProcessErr2Msg([]*Message{errMsg2})
		Expect(err).Should(BeNil())
		Expect(blamed).To(HaveKey(ID2))
	})
})
