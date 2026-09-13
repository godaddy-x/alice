// Copyright © 2022 AMIS Technologies
package sign

import "github.com/getamis/alice/crypto/tss/pairwise"

type digestRound = pairwise.Round

const (
	digestR1 = pairwise.Round1
	digestR2 = pairwise.Round2
	digestR3 = pairwise.Round3
)

type pairwiseDigestStore = pairwise.Store

func newPairwiseDigestStore() *pairwiseDigestStore {
	return pairwise.NewStore()
}
