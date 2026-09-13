// Copyright © 2022 AMIS Technologies
package pairwise

import "bytes"

// Gatekeeper binds pairwise digest store lookups to blame callbacks.
type Gatekeeper struct {
	DST   string
	SSID  []byte
	Store *Store
	Blame func(senderID string)
}

// AcceptTable validates and stores a finalized digest table from sender.
func (g *Gatekeeper) AcceptTable(round Round, roundTag, sender string, expectedPeers []string, entries []Entry, root []byte) error {
	tab, err := ValidateTable(g.DST, g.SSID, roundTag, sender, expectedPeers, entries, root)
	if err != nil {
		if g.Blame != nil {
			g.Blame(sender)
		}
		return err
	}
	g.Store.SetFinalized(round, sender, tab)
	return nil
}

// GateEdgeDigest verifies a reveal against the stored edge digest.
func (g *Gatekeeper) GateEdgeDigest(round Round, sender, self string, compute func() ([]byte, error)) error {
	want, ok := g.Store.Get(round, sender, self)
	if !ok {
		if g.Blame != nil {
			g.Blame(sender)
		}
		return ErrDigestBarrier
	}
	got, err := compute()
	if err != nil {
		if g.Blame != nil {
			g.Blame(sender)
		}
		return err
	}
	if !bytes.Equal(got, want) {
		if g.Blame != nil {
			g.Blame(sender)
		}
		return ErrPairwiseDigestMismatch
	}
	return nil
}
