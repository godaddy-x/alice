// Copyright © 2022 AMIS Technologies
package pairwise

import (
	"bytes"
	"encoding/binary"
	"hash"
	"sort"

	"github.com/minio/blake2b-simd"
)

const (
	DigestLen = 32
	tagRoot   = "ROOT"
)

// Entry is one row in a pairwise digest table.
type Entry struct {
	PeerID string
	Digest []byte
}

func writeLP(h hash.Hash, b []byte) {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(b)))
	_, _ = h.Write(lb[:])
	_, _ = h.Write(b)
}

// EdgeDigest computes H(dst, ssid, roundTag, sender, recipient, payload).
func EdgeDigest(dst string, ssid []byte, roundTag, sender, recipient string, payload []byte) []byte {
	h := blake2b.New256()
	_, _ = h.Write([]byte(dst))
	writeLP(h, ssid)
	writeLP(h, []byte(roundTag))
	writeLP(h, []byte(sender))
	writeLP(h, []byte(recipient))
	writeLP(h, payload)
	return h.Sum(nil)
}

func sortEntries(in []Entry) []Entry {
	out := make([]Entry, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		return out[i].PeerID < out[j].PeerID
	})
	return out
}

func tableRoot(dst string, ssid []byte, roundTag, sender string, entries []Entry) []byte {
	sorted := sortEntries(entries)
	h := blake2b.New256()
	_, _ = h.Write([]byte(dst))
	writeLP(h, ssid)
	writeLP(h, []byte(roundTag))
	writeLP(h, []byte(tagRoot))
	writeLP(h, []byte(sender))
	for _, e := range sorted {
		writeLP(h, []byte(e.PeerID))
		writeLP(h, e.Digest)
	}
	return h.Sum(nil)
}

// ValidateTable checks completeness against expectedPeers and table_root.
func ValidateTable(dst string, ssid []byte, roundTag, sender string, expectedPeers []string, entries []Entry, root []byte) (map[string][]byte, error) {
	if len(entries) != len(expectedPeers) {
		return nil, ErrPairwiseDigestTable
	}
	want := make(map[string]struct{}, len(expectedPeers))
	for _, id := range expectedPeers {
		want[id] = struct{}{}
	}
	tab := make(map[string][]byte, len(entries))
	for _, e := range entries {
		if e.PeerID == "" || len(e.Digest) != DigestLen {
			return nil, ErrPairwiseDigestTable
		}
		if _, ok := want[e.PeerID]; !ok {
			return nil, ErrPairwiseDigestTable
		}
		if _, dup := tab[e.PeerID]; dup {
			return nil, ErrPairwiseDigestTable
		}
		tab[e.PeerID] = append([]byte(nil), e.Digest...)
		delete(want, e.PeerID)
	}
	if len(want) != 0 {
		return nil, ErrPairwiseDigestTable
	}
	gotRoot := tableRoot(dst, ssid, roundTag, sender, entries)
	if !bytes.Equal(gotRoot, root) {
		return nil, ErrDigestTableRoot
	}
	return tab, nil
}

// BuildSortedEntries returns peer-id sorted digest rows.
func BuildSortedEntries(digests map[string][]byte) []Entry {
	return buildSortedEntries(digests)
}

// TableRoot recomputes table_root for the given entries.
func TableRoot(dst string, ssid []byte, roundTag, sender string, entries []Entry) []byte {
	return tableRoot(dst, ssid, roundTag, sender, entries)
}

func buildSortedEntries(digests map[string][]byte) []Entry {
	ids := make([]string, 0, len(digests))
	for id := range digests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Entry, 0, len(ids))
	for _, id := range ids {
		out = append(out, Entry{
			PeerID: id,
			Digest: append([]byte(nil), digests[id]...),
		})
	}
	return out
}

// CommitTable builds sorted entries and table_root for broadcast.
func CommitTable(dst string, ssid []byte, roundTag, sender string, digests map[string][]byte) ([]Entry, []byte) {
	entries := buildSortedEntries(digests)
	return entries, tableRoot(dst, ssid, roundTag, sender, entries)
}
