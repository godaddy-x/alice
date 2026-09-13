// Copyright © 2022 AMIS Technologies
package sign

import (
	"sync"
)

type digestRound int

const (
	digestR1 digestRound = iota
	digestR2
	digestR3
)

// pairwiseDigestStore holds Echo-finalized digest tables.
type pairwiseDigestStore struct {
	mu sync.Mutex
	// tables[round][sender] -> map[recipient]digest
	tables map[digestRound]map[string]map[string][]byte
}

func newPairwiseDigestStore() *pairwiseDigestStore {
	return &pairwiseDigestStore{
		tables: map[digestRound]map[string]map[string][]byte{
			digestR1: {},
			digestR2: {},
			digestR3: {},
		},
	}
}

func (s *pairwiseDigestStore) SetFinalized(round digestRound, sender string, tab map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(map[string][]byte, len(tab))
	for k, v := range tab {
		cp[k] = append([]byte(nil), v...)
	}
	s.tables[round][sender] = cp
}

func (s *pairwiseDigestStore) Get(round digestRound, sender, recipient string) ([]byte, bool) {
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

func (s *pairwiseDigestStore) hasAny(round digestRound) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tables[round]) > 0
}
