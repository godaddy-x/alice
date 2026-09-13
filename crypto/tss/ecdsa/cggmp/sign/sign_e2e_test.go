// Copyright © 2022 AMIS Technologies
package sign

import (
	"time"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/stretchr/testify/mock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sign E2E", func() {
	It("3-party honest sign succeeds with matching signature", func() {
		signs, _, listeners := buildSigns(3, nil)
		startAllAndWaitDone(signs, listeners)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
		assertMatchingSignResults(signs, 3)
	})

	It("9-party honest sign succeeds with matching signature", func() {
		signs, _, listeners := buildSigns(9, nil)
		startAllAndWaitDone(signs, listeners)
		for _, l := range listeners {
			l.AssertExpectations(GinkgoT())
		}
		assertMatchingSignResults(signs, 9)
	})

	It("3-party Round2 equivocation fails victim and blames attacker", func() {
		id1 := tss.GetTestID(1)
		id2 := tss.GetTestID(2)
		signs, _, listeners := buildSigns(3, map[int]string{1: id2})

		failed2 := make(chan struct{})
		listeners[id2].On("OnStateChanged", types.StateInit, types.StateFailed).Run(func(_ mock.Arguments) {
			close(failed2)
		}).Once()

		for _, s := range signs {
			s.Start()
		}

		Eventually(failed2, 15*time.Second).Should(BeClosed())
		Expect(signs[id2].GetState()).To(Equal(types.StateFailed))

		blamed, err := signs[id2].GetBlamedPeers()
		Expect(err).Should(BeNil())
		Expect(blamed).To(HaveKey(id1))

		_, err = signs[id2].GetResult()
		Expect(err).NotTo(BeNil())
	})
})
