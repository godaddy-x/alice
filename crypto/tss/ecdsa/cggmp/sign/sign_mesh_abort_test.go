package sign

import (
	"testing"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	. "github.com/onsi/gomega"
)

func registerTestFailHandler(t *testing.T) {
	t.Helper()
	RegisterFailHandler(func(message string, callerSkip ...int) {
		t.Helper()
		t.Fatal(message)
	})
}

func TestMeshErr1AbortE2E(t *testing.T) {
	registerTestFailHandler(t)

	detectorID := tss.GetTestID(0)
	attackerID := tss.GetTestID(1)
	defer installErr1AttackerDeltaTamper(detectorID, attackerID)()

	signs, _, listeners := buildSigns(3, nil)
	setMeshAbortCollectTimeout(signs)
	startAllSignMesh(signs, listeners)

	for id, s := range signs {
		waitForState(t, s, types.StateFailed, meshAbortTestTimeout)
		if id != detectorID {
			continue
		}
		blamed, err := s.GetBlamedPeers()
		if err != nil {
			t.Fatalf("detector GetBlamedPeers: %v", err)
		}
		if _, ok := blamed[attackerID]; !ok {
			t.Fatalf("detector expected blame %s, got %v", attackerID, blamed)
		}
	}
}

func TestMeshErr2AbortE2E(t *testing.T) {
	registerTestFailHandler(t)

	attackerID := tss.GetTestID(0)
	victimID := tss.GetTestID(1)

	signs, _, listeners := buildSignsWithRound4Tamper(2, map[int][]string{
		0: {victimID},
	})
	setMeshAbortCollectTimeout(signs)
	startAllSignMesh(signs, listeners)
	waitForState(t, signs[victimID], types.StateFailed, meshAbortTestTimeout)

	blamed, err := signs[victimID].GetBlamedPeers()
	if err != nil {
		t.Fatalf("GetBlamedPeers: %v", err)
	}
	if _, ok := blamed[attackerID]; !ok {
		t.Fatalf("expected victim to blame %s, got %v", attackerID, blamed)
	}
	snap := signs[victimID].abortCollector.Snapshot()
	if len(snap) == 0 || snap[0].Type != Type_Err2 {
		t.Fatalf("expected collected Err2 broadcast, got %v", snap)
	}
	if got := signs[attackerID].GetState(); got != types.StateDone && got != types.StateFailed {
		t.Fatalf("unexpected attacker state %v", got)
	}
}
