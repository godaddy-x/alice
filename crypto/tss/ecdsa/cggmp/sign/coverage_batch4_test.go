package sign

import (
	"math/big"
	"strings"
	"testing"

	"github.com/getamis/alice/crypto/tss"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

func TestProcessErr1MsgThreePartyHonestRemote(t *testing.T) {
	handlers, errMsgs := setupErr1ThreePartyTesting(t)
	for i, h := range handlers {
		others := make([]*Message, 0, 2)
		for j, m := range errMsgs {
			if i != j {
				others = append(others, m)
			}
		}
		blamed, err := h.ProcessErr1Msg(others)
		if err != nil {
			t.Fatal(err)
		}
		if len(blamed) != 0 {
			t.Fatalf("party %d: expected no blame, got %v", i, blamed)
		}
	}
}

func TestProcessErr1MsgThreePartyGDeltaBlamesAllRemotes(t *testing.T) {
	handlers, errMsgs := setupErr1ThreePartyTesting(t)
	h := handlers[0]
	h.BigDelta = errTestG.ScalarMult(big.NewInt(99999))
	blamed, err := h.ProcessErr1Msg([]*Message{errMsgs[1], errMsgs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected party 1 blamed")
	}
	if _, ok := blamed[tss.GetTestID(2)]; !ok {
		t.Fatal("expected party 2 blamed")
	}
}

func TestBuildSigmaVerifyFailureMsgMissingChi(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	p4.chi = nil
	err := p4.buildSigmaVerifyFailureMsg()
	if err == nil {
		t.Fatal("expected missing chi error")
	}
	if !strings.Contains(err.Error(), "chi") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildSigmaVerifyFailureMsgMissingR(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	p4.R = nil
	if err := p4.buildSigmaVerifyFailureMsg(); err == nil {
		t.Fatal("expected missing R error")
	}
}

func TestBuildSigmaVerifyFailureMsgMissingMsg(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	p4.msg = nil
	if err := p4.buildSigmaVerifyFailureMsg(); err == nil {
		t.Fatal("expected missing msg error")
	}
}

func TestBuildSigmaVerifyFailureMsgBlamesInvalidPsihat(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	peer := p4.peers[tss.GetTestID(1)]
	peer.round2Data.psihatProoof = &paillierzkproof.PaillierAffAndGroupRangeMessage{S: []byte{0xff}}
	var blamed string
	p4.onBlamedPeers = func(m map[string]struct{}) {
		for id := range m {
			blamed = id
		}
	}
	if err := p4.buildSigmaVerifyFailureMsg(); err == nil {
		t.Fatal("expected psihat verify error")
	}
	if blamed != tss.GetTestID(1) {
		t.Fatalf("want peer blamed, got %q", blamed)
	}
}

func TestOnAbortErr1UsesPrebuiltErr1Message(t *testing.T) {
	p3, p2Err := setupRound3PairForErr1Testing(t)
	if err := p3.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	ready := p3.err1Msg
	if err := p2Err.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err1, Body: p2Err.err1Msg.Body}
	h, err := p3.onAbortErr1(log.New(), remote)
	if err != nil {
		t.Fatal(err)
	}
	if p3.err1Msg != ready {
		t.Fatal("onAbortErr1 should not rebuild err1 when already present")
	}
	if _, ok := h.(*err1Handler); !ok {
		t.Fatal("expected err1Handler")
	}
}

func TestOnAbortErr2UsesPrebuiltErr2Message(t *testing.T) {
	p4, p2Err := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	ready := p4.err2Msg
	if err := p2Err.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err2, Body: p2Err.err2Msg.Body}
	h, err := p4.onAbortErr2(log.New(), remote)
	if err != nil {
		t.Fatal(err)
	}
	if p4.err2Msg != ready {
		t.Fatal("onAbortErr2 should not rebuild err2 when already present")
	}
	if _, ok := h.(*err2Handler); !ok {
		t.Fatal("expected err2Handler")
	}
}

func TestErr1HandlerAbortCollectingMetadata(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	if err := p3.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	eh, err := newErr1Handler(p3, ErrInvalidDelta)
	if err != nil {
		t.Fatal(err)
	}
	if !eh.AbortCollecting() {
		t.Fatal("expected AbortCollecting")
	}
	if eh.GetRequiredMessageCount() != p3.peerNum+1 {
		t.Fatal("unexpected required count")
	}
	if eh.MessageType() != types.MessageType(Type_Err1) {
		t.Fatal("unexpected message type")
	}
}

func TestErr2HandlerAbortCollectingMetadata(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	eh, err := newErr2Handler(p4, ErrIncorrectSig)
	if err != nil {
		t.Fatal(err)
	}
	if !eh.AbortCollecting() {
		t.Fatal("expected AbortCollecting")
	}
	if eh.GetRequiredMessageCount() != p4.peerNum+1 {
		t.Fatal("unexpected required count")
	}
}
