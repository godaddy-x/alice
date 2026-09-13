package sign

import (
	"testing"

	"github.com/getamis/alice/crypto/tss/blame"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types"
)

func TestGetBlameResultSplitsDisjoint(t *testing.T) {
	s := &Sign{MessageMain: &stubMessageMain{state: types.StateFailed}}
	s.storeBlame(cggmp.BlameContributionFromConfirmed(map[string]struct{}{"evil": {}}))
	s.storeBlame(cggmp.BlameContributionFromSuspect(map[string]struct{}{"slow": {}, "evil": {}}))

	r, err := s.GetBlameResult()
	if err != nil {
		t.Fatal(err)
	}
	if !r.Disjoint() {
		t.Fatalf("Confirmed ∩ Suspect must be empty, got %+v", r)
	}
	if _, ok := r.Confirmed["evil"]; !ok {
		t.Fatal("evil should be Confirmed")
	}
	if _, ok := r.Suspect["evil"]; ok {
		t.Fatal("evil must not remain Suspect")
	}
	if _, ok := r.Suspect["slow"]; !ok {
		t.Fatal("slow should be Suspect")
	}
	union, err := s.GetBlamedPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(union) != 2 {
		t.Fatalf("union want 2, got %v", union)
	}
}

func TestAmbiguousMaskPolicyConfirmAllErrRemappedInProd(t *testing.T) {
	if blame.ConfirmAllErrAllowed() {
		t.Skip("debug build")
	}
	s := &Sign{ph: &round1Handler{}}
	s.SetAmbiguousMaskPolicy(blame.ConfirmAllErr)
	if s.ph.ambiguousMaskPolicy != blame.SuspectAllErr {
		t.Fatalf("prod must remap ConfirmAllErr → SuspectAllErr, got %v", s.ph.ambiguousMaskPolicy)
	}
}
