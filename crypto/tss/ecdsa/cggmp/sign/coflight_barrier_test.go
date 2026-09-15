// Copyright © 2022 AMIS Technologies
package sign

import (
	"testing"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types/message"
)

func TestCoFlightBarrierA7EchoNotComplete(t *testing.T) {
	b := newCoFlightBarrier()
	b.SetRevealDone(true)
	if err := b.EnsureCanNext(); err != ErrEchoNotComplete {
		t.Fatalf("got %v, want ErrEchoNotComplete", err)
	}
	b.SetEchoDone(true)
	if err := b.EnsureCanNext(); err != nil {
		t.Fatalf("both done: %v", err)
	}
}

func TestCoFlightBarrierA8ConflictPriority(t *testing.T) {
	b := newCoFlightBarrier()
	b.SetEchoDone(true)
	b.SetRevealDone(true)
	b.MarkEchoConflict()
	if err := b.EnsureCanNext(); err != ErrEchoConflict {
		t.Fatalf("got %v, want ErrEchoConflict", err)
	}
}

func TestCoFlightBarrierRevealNotComplete(t *testing.T) {
	b := newCoFlightBarrier()
	b.SetEchoDone(true)
	if err := b.EnsureCanNext(); err != ErrRevealNotComplete {
		t.Fatalf("got %v, want ErrRevealNotComplete", err)
	}
}

func TestCoFlightBarrierResetClearsDoneKeepsConflict(t *testing.T) {
	b := newCoFlightBarrier()
	b.SetEchoDone(true)
	b.SetRevealDone(true)
	b.MarkEchoConflict()
	b.Reset()
	echoDone, revealDone, conflict := b.Snapshot()
	if echoDone || revealDone {
		t.Fatalf("Reset should clear done flags")
	}
	if !conflict {
		t.Fatalf("Reset must not clear echoConflict (INV-3)")
	}
}

func TestCoFlightFinalizeIncompleteRejectsEQBypass(t *testing.T) {
	// Regression: with barrier present, incomplete Finalize must NOT take serial-legacy path.
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			coFlight:    newCoFlightBarrier(),
			peers:       map[string]*peer{"p1": {}},
			peerManager: &staticPM{self: "self"},
			peerNum:     1,
		},
		pendingRound1: map[string]*Message{"p1": {Id: "self", Type: Type_Round1}},
	}
	_, err := h.Finalize(nil)
	if err != ErrEchoNotComplete {
		t.Fatalf("got %v, want ErrEchoNotComplete (must not serial-legacy)", err)
	}
}

func TestCoFlightBarrierReadyHelpers(t *testing.T) {
	h := &round1Handler{coFlight: newCoFlightBarrier(), peerNum: 1}
	if h.coFlightReady() || h.coFlightComplete() {
		t.Fatal("empty barrier should not be ready/complete")
	}
	h.coFlight.SetEchoDone(true)
	h.coFlight.SetRevealDone(true)
	if !h.coFlightReady() || !h.coFlightComplete() {
		t.Fatal("both done should be ready and complete")
	}
	h.coFlight.MarkEchoConflict()
	if !h.coFlightReady() {
		t.Fatal("conflict should force ready so Finalize can abort")
	}
	if h.coFlightComplete() {
		t.Fatal("conflict must not be complete")
	}
	if err := h.rejectIfEchoConflict(); err != ErrEchoConflict {
		t.Fatalf("got %v", err)
	}
}

func TestCoFlightEarlyRevealRejectsStranger(t *testing.T) {
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			coFlight: newCoFlightBarrier(),
			peers:    map[string]*peer{"p1": {Peer: message.NewPeer("p1")}},
			peerNum:  1,
		},
		earlyRound1: make(map[string]*Message),
	}
	err := h.handleReveal(nil, &Message{Id: "stranger", Type: Type_Round1, Body: &Message_Round1{Round1: &Round1Msg{}}})
	if err != tss.ErrPeerNotFound {
		t.Fatalf("got %v, want ErrPeerNotFound", err)
	}
	if len(h.earlyRound1) != 0 {
		t.Fatal("stranger must not enter early reveal map")
	}
}

func TestCoFlightEarlyRevealRejectsOverwrite(t *testing.T) {
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			coFlight: newCoFlightBarrier(),
			peers:    map[string]*peer{"p1": {Peer: message.NewPeer("p1")}},
			peerNum:  1,
		},
		earlyRound1: make(map[string]*Message),
	}
	first := &Message{Id: "p1", Type: Type_Round1, Body: &Message_Round1{Round1: &Round1Msg{KCiphertext: []byte{1}}}}
	second := &Message{Id: "p1", Type: Type_Round1, Body: &Message_Round1{Round1: &Round1Msg{KCiphertext: []byte{2}}}}
	if err := h.handleReveal(nil, first); err != nil {
		t.Fatal(err)
	}
	if err := h.handleReveal(nil, second); err != message.ErrDupMsg {
		t.Fatalf("got %v, want ErrDupMsg", err)
	}
	if got := h.earlyRound1["p1"].GetRound1().GetKCiphertext(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("early reveal must stay first payload, got %v", got)
	}
}

func TestRound1DigestScheduleVersionMismatch(t *testing.T) {
	sender := "id-1"
	var blamed string
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			coFlight:    newCoFlightBarrier(),
			digestStore: newPairwiseDigestStore(),
			peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager: &staticPM{self: "id-0"},
			onBlame: func(c cggmp.BlameContribution) {
				for id := range c.Union() {
					blamed = id
				}
			},
		},
	}
	err := h.HandleMessage(nil, &Message{
		Id:   sender,
		Type: Type_Round1Digest,
		Body: &Message_Round1Digest{
			Round1Digest: &Round1DigestMsg{
				KCiphertext:     []byte("k"),
				GammaCiphertext: []byte("g"),
				ScheduleVersion: "serial-v1",
			},
		},
	})
	if err != ErrScheduleMismatch {
		t.Fatalf("got %v, want ErrScheduleMismatch", err)
	}
	if blamed != sender {
		t.Fatalf("want blame %s, got %q", sender, blamed)
	}
}

func TestRound1DigestScheduleVersionEmptyRejected(t *testing.T) {
	sender := "id-1"
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			coFlight:    newCoFlightBarrier(),
			digestStore: newPairwiseDigestStore(),
			peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager: &staticPM{self: "id-0"},
		},
	}
	err := h.HandleMessage(nil, &Message{
		Id:   sender,
		Type: Type_Round1Digest,
		Body: &Message_Round1Digest{
			Round1Digest: &Round1DigestMsg{
				ScheduleVersion: "",
			},
		},
	})
	if err != ErrScheduleMismatch {
		t.Fatalf("got %v, want ErrScheduleMismatch", err)
	}
}

func TestRound1DigestScheduleVersionTooLongRejected(t *testing.T) {
	sender := "id-1"
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			coFlight:    newCoFlightBarrier(),
			digestStore: newPairwiseDigestStore(),
			peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager: &staticPM{self: "id-0"},
		},
	}
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	err := h.HandleMessage(nil, &Message{
		Id:   sender,
		Type: Type_Round1Digest,
		Body: &Message_Round1Digest{
			Round1Digest: &Round1DigestMsg{ScheduleVersion: string(long)},
		},
	})
	if err != ErrScheduleMismatch {
		t.Fatalf("got %v, want ErrScheduleMismatch", err)
	}
}
