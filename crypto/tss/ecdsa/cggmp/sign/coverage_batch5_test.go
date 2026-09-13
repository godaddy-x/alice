package sign

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/tss"
)

func TestProcessErr1MsgIgnoresUnknownSender(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	unknown := &Message{Id: "unknown-party", Type: Type_Err1, Body: remote.Body}
	blamed, err := p3.ProcessErr1Msg([]*Message{remote, unknown})
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed.Union()) != 0 {
		t.Fatalf("expected no blame for valid remote, got %v", blamed)
	}
}

func TestProcessErr1MsgBlamesPeerNsLengthMismatch(t *testing.T) {
	handlers, errMsgs := setupErr1ThreePartyTesting(t)
	h := handlers[0]
	// Drop local peer-2 view; remote Err1 still lists component id-2.
	delete(h.peers, tss.GetTestID(2))
	blamed, err := h.ProcessErr1Msg([]*Message{errMsgs[1]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed when peerNs shorter than Err1 peers map")
	}
}

func TestProcessErr1MsgAggregateBlamesLocalMissingRound3(t *testing.T) {
	handlers, errMsgs := setupErr1ThreePartyTesting(t)
	h := handlers[0]
	h.peers[tss.GetTestID(1)].round3Data = nil
	blamed, err := h.ProcessErr1Msg([]*Message{errMsgs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected local peer blamed in aggregate for missing round3 data")
	}
}

func TestProcessErr1MsgBlamesTamperedD(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	entry := remote.GetErr1().Peers[tss.GetTestID(0)]
	if entry == nil || len(entry.D) == 0 {
		t.Fatal("missing D in err1 peer entry")
	}
	entry.D[0] ^= 0xff
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for tampered D")
	}
}

func TestProcessErr1MsgBlamesMissingDecModQProof(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	entry := remote.GetErr1().Peers[tss.GetTestID(0)]
	if entry == nil {
		t.Fatal("missing peer entry")
	}
	entry.DecModQ = nil
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for missing DecModQ")
	}
}

func TestBuildDeltaVerifyFailureMsgDecModQWitnessFails(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	curveN := errTestPublicKey.GetCurve().Params().N
	p3.delta = new(big.Int).Mod(big.NewInt(999999), curveN)
	if err := p3.buildDeltaVerifyFailureMsg(); err == nil {
		t.Fatal("expected decModQWitness/build failure with inconsistent delta")
	}
}

func TestBuildSigmaVerifyFailureMsgAttachErr2DecModQFails(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	curveN := errTestPublicKey.GetCurve().Params().N
	p4.chi = new(big.Int).Mod(big.NewInt(999999), curveN)
	if err := p4.buildSigmaVerifyFailureMsg(); err == nil {
		t.Fatal("expected attachErr2DecModQ/decModQWitness failure with inconsistent chi")
	}
}

func TestReconstructPaillierProductNonInvertibleF(t *testing.T) {
	nSquare := new(big.Int).Mul(big.NewInt(35), big.NewInt(35))
	_, ok := reconstructPaillierProduct(big.NewInt(11), nSquare, map[string][2]*big.Int{
		"p1": {big.NewInt(3), big.NewInt(35)},
	})
	if ok {
		t.Fatal("expected failure when F has no modular inverse")
	}
}

func TestProcessErr2MsgBlamesTamperedDhat(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	entry := remote.GetErr2().Peers[tss.GetTestID(0)]
	if entry == nil || len(entry.D) == 0 {
		t.Fatal("missing Dhat bytes in err2 peer entry")
	}
	entry.D[0] ^= 0xff
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for tampered Dhat")
	}
}

func TestProcessErr2MsgBlamesMissingDecModQProof(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	entry := remote.GetErr2().Peers[tss.GetTestID(0)]
	if entry == nil {
		t.Fatal("missing peer entry")
	}
	entry.DecModQ = nil
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for missing DecModQ")
	}
}
