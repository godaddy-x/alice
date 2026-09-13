// Copyright © 2022 AMIS Technologies
package signer

import (
	"encoding/binary"
	"sort"

	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/pairwise"
	"google.golang.org/protobuf/proto"
)

const (
	pairwiseDigestDST = "AMIS-Alice-FROST-Sign-Pairwise-Digest-v1"
	tagR1             = "R1"
	tagR2             = "R2"
)

func marshalDet(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

func frostEntries(in []*PeerDigestEntry) []pairwise.Entry {
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

func round1DigestPayload(bkX []byte, d, e *ecpointgrouplaw.ECPoint) ([]byte, error) {
	encodingD, err := ecpointEncoding(d)
	if err != nil {
		return nil, err
	}
	encodingE, err := ecpointEncoding(e)
	if err != nil {
		return nil, err
	}
	return marshalDet(&BMessage{
		X: append([]byte(nil), bkX...),
		D: encodingD[:],
		E: encodingE[:],
	})
}

func Round1PairwiseDigest(ssid []byte, sender, recipient string, bkX []byte, d, e *ecpointgrouplaw.ECPoint) ([]byte, error) {
	payload, err := round1DigestPayload(bkX, d, e)
	if err != nil {
		return nil, err
	}
	return pairwise.EdgeDigest(pairwiseDigestDST, ssid, tagR1, sender, recipient, payload), nil
}

func Round2PairwiseDigest(ssid []byte, sender, recipient string, zi []byte) []byte {
	payload := append([]byte(nil), zi...)
	return pairwise.EdgeDigest(pairwiseDigestDST, ssid, tagR2, sender, recipient, payload)
}

func validateDigestTable(ssid []byte, roundTag, sender string, expectedPeers []string, entries []*PeerDigestEntry, root []byte) (map[string][]byte, error) {
	return pairwise.ValidateTable(pairwiseDigestDST, ssid, roundTag, sender, expectedPeers, frostEntries(entries), root)
}

func commitDigestTable(ssid []byte, roundTag, sender string, digests map[string][]byte) ([]*PeerDigestEntry, []byte) {
	entries, root := pairwise.CommitTable(pairwiseDigestDST, ssid, roundTag, sender, digests)
	return peerDigestEntries(entries), root
}

func appendWithLength(buf []byte, data []byte) []byte {
	lb := make([]byte, 4)
	binary.BigEndian.PutUint32(lb, uint32(len(data)))
	return append(append(buf, lb...), data...)
}

// ComputeFrostSignSSID binds the sign session to DKG ssid, message, pubkey, threshold, peers.
func ComputeFrostSignSSID(dkgSSID, msg, pubKeyBytes []byte, threshold uint32, peerIDs []string) []byte {
	sorted := append([]string(nil), peerIDs...)
	sort.Strings(sorted)
	total := 4 + len(dkgSSID) + 4 + len(msg) + 4 + len(pubKeyBytes) + 4 + len(sorted)*32
	out := make([]byte, 0, total)
	out = appendWithLength(out, dkgSSID)
	out = appendWithLength(out, msg)
	out = appendWithLength(out, pubKeyBytes)
	tb := make([]byte, 4)
	binary.BigEndian.PutUint32(tb, threshold)
	out = append(out, tb...)
	for _, id := range sorted {
		out = appendWithLength(out, []byte(id))
	}
	return out
}
