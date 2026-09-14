// Copyright © 2022 AMIS Technologies
package sign

import "testing"

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
