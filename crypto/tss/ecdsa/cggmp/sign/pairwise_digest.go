// Copyright © 2022 AMIS Technologies
package sign

import (
	"google.golang.org/protobuf/proto"

	"github.com/getamis/alice/crypto/tss/pairwise"
)

const (
	// v3: length-prefixed variable fields (ssid / ids / payload) for domain separation.
	pairwiseDigestDST = "AMIS-Alice-CGGMP-Sign-Pairwise-Digest-v3"

	tagR1   = "R1"
	tagR2   = "R2"
	tagR3   = "R3"
	tagRoot = "ROOT"
)

const digestLen = pairwise.DigestLen

var (
	ErrPairwiseDigestMismatch = pairwise.ErrPairwiseDigestMismatch
	ErrPairwiseDigestTable    = pairwise.ErrPairwiseDigestTable
	ErrDigestBarrier          = pairwise.ErrDigestBarrier
	ErrDigestTableRoot        = pairwise.ErrDigestTableRoot
)

func marshalDet(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

func cggmpEntries(in []*PeerDigestEntry) []pairwise.Entry {
	out := make([]pairwise.Entry, 0, len(in))
	for _, e := range in {
		if e == nil {
			continue
		}
		out = append(out, pairwise.Entry{
			PeerID: e.GetPeerId(),
			Digest: append([]byte(nil), e.GetDigest()...),
		})
	}
	return out
}

func peerDigestEntries(entries []pairwise.Entry) []*PeerDigestEntry {
	out := make([]*PeerDigestEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, &PeerDigestEntry{
			PeerId: e.PeerID,
			Digest: append([]byte(nil), e.Digest...),
		})
	}
	return out
}

func edgeDigest(ssid []byte, roundTag, sender, recipient string, payload []byte) []byte {
	return pairwise.EdgeDigest(pairwiseDigestDST, ssid, roundTag, sender, recipient, payload)
}

// ValidateDigestTable checks completeness against expectedPeers and table_root.
func ValidateDigestTable(ssid []byte, roundTag, sender string, expectedPeers []string, entries []*PeerDigestEntry, root []byte) (map[string][]byte, error) {
	return pairwise.ValidateTable(pairwiseDigestDST, ssid, roundTag, sender, expectedPeers, cggmpEntries(entries), root)
}

func commitDigestTable(ssid []byte, roundTag, sender string, digests map[string][]byte) ([]*PeerDigestEntry, []byte) {
	entries, root := pairwise.CommitTable(pairwiseDigestDST, ssid, roundTag, sender, digests)
	return peerDigestEntries(entries), root
}

func buildSortedEntries(digests map[string][]byte) []*PeerDigestEntry {
	return peerDigestEntries(pairwise.BuildSortedEntries(digests))
}

func tableRoot(ssid []byte, roundTag, sender string, entries []*PeerDigestEntry) []byte {
	return pairwise.TableRoot(pairwiseDigestDST, ssid, roundTag, sender, cggmpEntries(entries))
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
