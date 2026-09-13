package pairwise

import "testing"

func TestGatekeeperBarrierAndMismatch(t *testing.T) {
	dst := "AMIS-Alice-Test-Pairwise-Digest"
	ssid := []byte("ssid")
	blamed := ""
	gk := &Gatekeeper{
		DST:   dst,
		SSID:  ssid,
		Store: NewStore(),
		Blame: func(id string) { blamed = id },
	}
	if err := gk.GateEdgeDigest(Round1, "peer", "self", func() ([]byte, error) {
		return make([]byte, DigestLen), nil
	}); err != ErrDigestBarrier {
		t.Fatalf("expected barrier, got %v", err)
	}
	if blamed != "peer" {
		t.Fatalf("expected peer blamed, got %q", blamed)
	}

	want := EdgeDigest(dst, ssid, "R1", "peer", "self", []byte("x"))
	gk.Store.SetFinalized(Round1, "peer", map[string][]byte{"self": want})
	blamed = ""
	if err := gk.GateEdgeDigest(Round1, "peer", "self", func() ([]byte, error) {
		return EdgeDigest(dst, ssid, "R1", "peer", "self", []byte("y")), nil
	}); err != ErrPairwiseDigestMismatch {
		t.Fatalf("expected mismatch, got %v", err)
	}
	if blamed != "peer" {
		t.Fatalf("expected peer blamed on mismatch, got %q", blamed)
	}
}
