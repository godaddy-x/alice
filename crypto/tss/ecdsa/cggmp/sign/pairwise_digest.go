// Copyright © 2022 AMIS Technologies
package sign

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"sort"

	"github.com/minio/blake2b-simd"
	"google.golang.org/protobuf/proto"
)

const (
	// v3: length-prefixed variable fields (ssid / ids / payload) for domain separation.
	pairwiseDigestDST = "AMIS-Alice-CGGMP-Sign-Pairwise-Digest-v3"
	digestLen         = 32

	tagR1   = "R1"
	tagR2   = "R2"
	tagR3   = "R3"
	tagRoot = "ROOT"
)

var (
	ErrPairwiseDigestMismatch = errors.New("pairwise digest mismatch")
	ErrPairwiseDigestTable    = errors.New("invalid pairwise digest table")
	ErrDigestBarrier          = errors.New("pairwise digest barrier not ready")
	ErrDigestTableRoot        = errors.New("pairwise digest table_root mismatch")
)

func marshalDet(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

func writeLP(h hash.Hash, b []byte) {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(b)))
	_, _ = h.Write(lb[:])
	_, _ = h.Write(b)
}

func edgeDigest(ssid []byte, roundTag, sender, recipient string, payload []byte) []byte {
	h := blake2b.New256()
	_, _ = h.Write([]byte(pairwiseDigestDST))
	writeLP(h, ssid)
	writeLP(h, []byte(roundTag))
	writeLP(h, []byte(sender))
	writeLP(h, []byte(recipient))
	writeLP(h, payload)
	return h.Sum(nil)
}

func tableRoot(ssid []byte, roundTag, sender string, entries []*PeerDigestEntry) []byte {
	sorted := sortEntries(entries)
	h := blake2b.New256()
	_, _ = h.Write([]byte(pairwiseDigestDST))
	writeLP(h, ssid)
	writeLP(h, []byte(roundTag))
	writeLP(h, []byte(tagRoot))
	writeLP(h, []byte(sender))
	for _, e := range sorted {
		writeLP(h, []byte(e.GetPeerId()))
		writeLP(h, e.GetDigest())
	}
	return h.Sum(nil)
}

func sortEntries(in []*PeerDigestEntry) []*PeerDigestEntry {
	out := make([]*PeerDigestEntry, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		return out[i].GetPeerId() < out[j].GetPeerId()
	})
	return out
}

// ValidateDigestTable checks completeness against expectedPeers and table_root.
func ValidateDigestTable(ssid []byte, roundTag, sender string, expectedPeers []string, entries []*PeerDigestEntry, root []byte) (map[string][]byte, error) {
	if len(entries) != len(expectedPeers) {
		return nil, ErrPairwiseDigestTable
	}
	want := make(map[string]struct{}, len(expectedPeers))
	for _, id := range expectedPeers {
		want[id] = struct{}{}
	}
	tab := make(map[string][]byte, len(entries))
	for _, e := range entries {
		if e == nil || len(e.GetDigest()) != digestLen {
			return nil, ErrPairwiseDigestTable
		}
		id := e.GetPeerId()
		if _, ok := want[id]; !ok {
			return nil, ErrPairwiseDigestTable
		}
		if _, dup := tab[id]; dup {
			return nil, ErrPairwiseDigestTable
		}
		tab[id] = append([]byte(nil), e.GetDigest()...)
		delete(want, id)
	}
	if len(want) != 0 {
		return nil, ErrPairwiseDigestTable
	}
	gotRoot := tableRoot(ssid, roundTag, sender, entries)
	if !bytes.Equal(gotRoot, root) {
		return nil, ErrDigestTableRoot
	}
	return tab, nil
}

func buildSortedEntries(digests map[string][]byte) []*PeerDigestEntry {
	ids := make([]string, 0, len(digests))
	for id := range digests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*PeerDigestEntry, 0, len(ids))
	for _, id := range ids {
		out = append(out, &PeerDigestEntry{
			PeerId: id,
			Digest: append([]byte(nil), digests[id]...),
		})
	}
	return out
}

func commitDigestTable(ssid []byte, roundTag, sender string, digests map[string][]byte) ([]*PeerDigestEntry, []byte) {
	entries := buildSortedEntries(digests)
	return entries, tableRoot(ssid, roundTag, sender, entries)
}

func Round1PsiDigest(ssid []byte, sender, recipient string, psi proto.Message) ([]byte, error) {
	payload, err := marshalDet(psi)
	if err != nil {
		return nil, err
	}
	return edgeDigest(ssid, tagR1, sender, recipient, payload), nil
}

func Round2PairwiseDigest(ssid []byte, sender, recipient string, r2 *Round2Msg) ([]byte, error) {
	if r2 == nil {
		return nil, ErrPairwiseDigestTable
	}
	canon := &Round2Msg{
		D:      r2.GetD(),
		F:      r2.GetF(),
		Dhat:   r2.GetDhat(),
		Fhat:   r2.GetFhat(),
		Psi:    r2.GetPsi(),
		Psihat: r2.GetPsihat(),
		Psipai: r2.GetPsipai(),
		// Gamma excluded — committed in Round2Digest header
	}
	payload, err := marshalDet(canon)
	if err != nil {
		return nil, err
	}
	return edgeDigest(ssid, tagR2, sender, recipient, payload), nil
}

func Round3PairwiseDigest(ssid []byte, sender, recipient string, psi proto.Message) ([]byte, error) {
	payload, err := marshalDet(psi)
	if err != nil {
		return nil, err
	}
	return edgeDigest(ssid, tagR3, sender, recipient, payload), nil
}
