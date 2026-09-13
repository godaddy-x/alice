// Copyright © 2022 AMIS Technologies
package signer

import "errors"

var ErrBlamedPeersNotReady = errors.New("blamed peers not ready until StateFailed")

const maxFrostSignPeers = 9

func validateParticipantCount(n int) error {
	if n <= 0 || n > maxFrostSignPeers {
		return errors.New("invalid frost sign participant count")
	}
	return nil
}
