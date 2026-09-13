// Copyright © 2022 AMIS Technologies
package pairwise

import "sync"

// Round identifies a digest barrier round.
type Round int

const (
	Round1 Round = iota
	Round2
	Round3
)

// Store holds Echo-finalized digest tables.
type Store struct {
	mu sync.Mutex
	// tables[round][sender] -> map[recipient]digest
	tables map[Round]map[string]map[string][]byte
}

func NewStore() *Store {
	return &Store{
		tables: map[Round]map[string]map[string][]byte{
			Round1: {},
			Round2: {},
			Round3: {},
		},
	}
}

func (s *Store) SetFinalized(round Round, sender string, tab map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(map[string][]byte, len(tab))
	for k, v := range tab {
		cp[k] = append([]byte(nil), v...)
	}
	s.tables[round][sender] = cp
}

func (s *Store) Get(round Round, sender, recipient string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tab, ok := s.tables[round][sender]
	if !ok {
		return nil, false
	}
	d, ok := tab[recipient]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), d...), true
}

func (s *Store) HasAny(round Round) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tables[round]) > 0
}
