package sign

import (
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sign limits", func() {
	It("NewSign rejects more than 9 participants", func() {
		const lens = 10
		ensureSignTestPailliers(lens)
		bks, shares, partialPubKey, pub, allPed := buildTestCredentials(lens, signTestPeds[:lens])
		pm := tss.NewTestPeerManager(0, lens)
		listener := new(mocks.StateChangedListener)

		_, err := NewSign(
			threshold,
			[]byte("limits"),
			shares[0],
			pub,
			partialPubKey,
			signTestPaillierKeys[0],
			allPed,
			bks,
			msg,
			pm,
			listener,
		)
		Expect(err).Should(Equal(cggmp.ErrTooManyPeersForIA))
	})
})
