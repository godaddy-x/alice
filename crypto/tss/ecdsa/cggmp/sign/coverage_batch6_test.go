package sign

import (
	"testing"

	"github.com/getamis/alice/crypto/tss"
)

func TestProcessErr2MsgThreePartyHonestRemote(t *testing.T) {
	handlers, errMsgs := setupErr2ThreePartyTesting(t)
	for i, h := range handlers {
		others := make([]*Message, 0, 2)
		for j, m := range errMsgs {
			if i != j {
				others = append(others, m)
			}
		}
		blamed, err := h.ProcessErr2Msg(others)
		if err != nil {
			t.Fatal(err)
		}
		if len(blamed.Union()) != 0 {
			t.Fatalf("party %d: expected no blame, got %v", i, blamed)
		}
	}
}

func TestProcessErr2MsgBlamesPeerNsLengthMismatch(t *testing.T) {
	handlers, errMsgs := setupErr2ThreePartyTesting(t)
	h := handlers[0]
	delete(h.peers, tss.GetTestID(2))
	blamed, err := h.ProcessErr2Msg([]*Message{errMsgs[1]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed when peerNs shorter than Err2 peers map")
	}
}

func TestProcessErr2MsgIgnoresUnknownSender(t *testing.T) {
	handlers, errMsgs := setupErr2ThreePartyTesting(t)
	h := handlers[0]
	unknown := &Message{Id: "unknown-party", Type: Type_Err2, Body: errMsgs[1].Body}
	blamed, err := h.ProcessErr2Msg([]*Message{errMsgs[1], errMsgs[2], unknown})
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed.Union()) != 0 {
		t.Fatalf("expected no blame for valid remote, got %v", blamed)
	}
}

func TestProcessErr2MsgBlamesTamperedFhat(t *testing.T) {
	handlers, errMsgs := setupErr2ThreePartyTesting(t)
	h := handlers[0]
	entry := errMsgs[1].GetErr2().Peers[tss.GetTestID(0)]
	if entry == nil || len(entry.F) == 0 {
		t.Fatal("missing Fhat bytes in err2 peer entry")
	}
	entry.F[0] ^= 0xff
	blamed, err := h.ProcessErr2Msg([]*Message{errMsgs[1]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for tampered Fhat")
	}
}

func TestProcessErr2MsgBlamesMissingRound1Data(t *testing.T) {
	handlers, errMsgs := setupErr2ThreePartyTesting(t)
	h := handlers[0]
	h.peers[tss.GetTestID(1)].round1Data = nil
	blamed, err := h.ProcessErr2Msg([]*Message{errMsgs[1]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for missing round1 data")
	}
}

func TestProcessErr2MsgBlamesNilErr2Body(t *testing.T) {
	handlers, errMsgs := setupErr2ThreePartyTesting(t)
	h := handlers[0]
	bad := &Message{Id: tss.GetTestID(1), Type: Type_Err2, Body: nil}
	_ = errMsgs
	blamed, err := h.ProcessErr2Msg([]*Message{bad})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for nil err2 body")
	}
}

func TestProcessErr2MsgBlamesMissingSelfEntry(t *testing.T) {
	handlers, errMsgs := setupErr2ThreePartyTesting(t)
	h := handlers[0]
	body := errMsgs[1].GetErr2()
	delete(body.Peers, tss.GetTestID(0))
	blamed, err := h.ProcessErr2Msg([]*Message{errMsgs[1]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed when self entry missing from err2 peers map")
	}
}
