// Copyright © 2022 AMIS Technologies
//
package sign

import (
	"errors"
	"sync"
)

var (
	// ErrEchoNotComplete is returned when Finalize is attempted before digest Echo
	// collection completes (INV-1).
	ErrEchoNotComplete = errors.New("coflight: echo not complete")
	// ErrRevealNotComplete is returned when Finalize is attempted before reveals
	// are collected.
	ErrRevealNotComplete = errors.New("coflight: reveal not complete")
	// ErrEchoConflict is returned when Echo equivocation was observed (INV-2).
	ErrEchoConflict = errors.New("coflight: echo conflict")
	// ErrScheduleMismatch is returned when Round1Digest.schedule_version differs
	// from the local SignScheduleVersion (mixed serial/coflight peers).
	ErrScheduleMismatch = errors.New("coflight: sign schedule version mismatch")
)

// SignScheduleVersion identifies the success-path scheduling dialect.
// Sessions must not mix serial-v1 and coflight-v1 peers.
const SignScheduleVersion = "coflight-v1"

// coFlightBarrier is the outer guard for Digest Echo‖Reveal co-flight.
// It is the only place that may authorize Next from a CoFlight stage (INV-1/2/3).
type coFlightBarrier struct {
	mu           sync.Mutex
	echoDone     bool
	revealDone   bool
	echoConflict bool
}

func newCoFlightBarrier() *coFlightBarrier {
	return &coFlightBarrier{}
}

func (c *coFlightBarrier) MarkEchoConflict() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.echoConflict = true
}

func (c *coFlightBarrier) HasEchoConflict() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.echoConflict
}

func (c *coFlightBarrier) SetEchoDone(v bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.echoDone = v
}

func (c *coFlightBarrier) SetRevealDone(v bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revealDone = v
}

func (c *coFlightBarrier) Snapshot() (echoDone, revealDone, echoConflict bool) {
	if c == nil {
		return false, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.echoDone, c.revealDone, c.echoConflict
}

// EnsureCanNext enforces INV-1/2/3 at the CoFlight Finalize entry.
// A nil barrier is treated as serial-legacy (no guard).
func (c *coFlightBarrier) EnsureCanNext() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.echoConflict {
		return ErrEchoConflict
	}
	if !c.echoDone {
		return ErrEchoNotComplete
	}
	if !c.revealDone {
		return ErrRevealNotComplete
	}
	return nil
}

// Reset clears per-round done flags after a successful Next.
// echoConflict stays latched for the session (INV-3).
func (c *coFlightBarrier) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.echoDone = false
	c.revealDone = false
}
