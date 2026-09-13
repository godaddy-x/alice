// Copyright © 2022 AMIS Technologies
package pairwise

import "errors"

var (
	ErrPairwiseDigestMismatch = errors.New("pairwise digest mismatch")
	ErrPairwiseDigestTable    = errors.New("invalid pairwise digest table")
	ErrDigestBarrier          = errors.New("pairwise digest barrier not ready")
	ErrDigestTableRoot        = errors.New("pairwise digest table_root mismatch")
)
