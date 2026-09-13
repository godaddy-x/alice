package sign

import (
	"bytes"
	"testing"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

func TestEdgeDigestStableAndSensitive(t *testing.T) {
	ssid := []byte("ssid")
	d1 := edgeDigest(ssid, tagR2, "a", "b", []byte("payload"))
	d2 := edgeDigest(ssid, tagR2, "a", "b", []byte("payload"))
	if !bytes.Equal(d1, d2) {
		t.Fatal("digest not stable")
	}
	if len(d1) != digestLen {
		t.Fatalf("digest len %d", len(d1))
	}
	d3 := edgeDigest(ssid, tagR2, "a", "b", []byte("payloae"))
	if bytes.Equal(d1, d3) {
		t.Fatal("digest should change on payload flip")
	}
}

func TestValidateDigestTable(t *testing.T) {
	ssid := []byte("ssid")
	sender := "s"
	peers := []string{"p1", "p2"}
	digests := map[string][]byte{
		"p1": edgeDigest(ssid, tagR1, sender, "p1", []byte("a")),
		"p2": edgeDigest(ssid, tagR1, sender, "p2", []byte("b")),
	}
	entries := buildSortedEntries(digests)
	root := tableRoot(ssid, tagR1, sender, entries)

	tab, err := ValidateDigestTable(ssid, tagR1, sender, peers, entries, root)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digests["p1"], tab["p1"]) {
		t.Fatal("tab mismatch")
	}

	if _, err := ValidateDigestTable(ssid, tagR1, sender, peers, entries[:1], root); err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}

	badRoot := append([]byte(nil), root...)
	badRoot[0] ^= 1
	if _, err := ValidateDigestTable(ssid, tagR1, sender, peers, entries, badRoot); err != ErrDigestTableRoot {
		t.Fatalf("want root err, got %v", err)
	}
}

func TestRound2PairwiseDigestExcludesGamma(t *testing.T) {
	ssid := []byte("ssid")
	r2a := &Round2Msg{D: []byte{1}, F: []byte{2}, Dhat: []byte{3}, Fhat: []byte{4}}
	r2b := &Round2Msg{D: []byte{1}, F: []byte{2}, Dhat: []byte{3}, Fhat: []byte{4}}
	d1, err := Round2PairwiseDigest(ssid, "i", "j", r2a)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Round2PairwiseDigest(ssid, "i", "j", r2b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d1, d2) {
		t.Fatal("gamma-less digests should match")
	}
	r2a.D = []byte{9}
	d3, err := Round2PairwiseDigest(ssid, "i", "j", r2a)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(d1, d3) {
		t.Fatal("D flip should change digest")
	}
}

func TestEdgeDigestLengthPrefixSeparatesIDs(t *testing.T) {
	ssid := []byte("ssid")
	// Without length prefixes, sender "a\x00b" / recipient "c" collides with
	// sender "a" / recipient "b\x00c" under the old 0x00 delimiter scheme.
	d1 := edgeDigest(ssid, tagR1, "a\x00b", "c", []byte("payload"))
	d2 := edgeDigest(ssid, tagR1, "a", "b\x00c", []byte("payload"))
	if bytes.Equal(d1, d2) {
		t.Fatal("length-prefixed edge digest must separate id boundaries")
	}
}

func TestGateEdgeDigestMismatchBlames(t *testing.T) {
	ssid := []byte("ssid")
	self := "self"
	sender := "evil"
	h := &round1Handler{
		ssid:        ssid,
		digestStore: newPairwiseDigestStore(),
		peerManager: &staticPM{self: self},
	}
	var blamed string
	h.onBlamedPeers = func(m map[string]struct{}) {
		for id := range m {
			blamed = id
		}
	}
	want := edgeDigest(ssid, tagR2, sender, self, []byte("committed"))
	h.digestStore.SetFinalized(digestR2, sender, map[string][]byte{self: want})

	err := h.gateEdgeDigest(digestR2, sender, self, func() ([]byte, error) {
		return edgeDigest(ssid, tagR2, sender, self, []byte("opened-differently")), nil
	})
	if err != ErrPairwiseDigestMismatch {
		t.Fatalf("want mismatch, got %v", err)
	}
	if blamed != sender {
		t.Fatalf("want blame %s, got %q", sender, blamed)
	}
}

func TestAcceptDigestTableBlamesIncomplete3Party(t *testing.T) {
	ssid := []byte("3p")
	sender := "evil"
	self := "honest"
	peers := map[string]*peer{
		"p2": {Peer: message.NewPeer("p2")},
		"p3": {Peer: message.NewPeer("p3")},
	}
	h := &round1Handler{
		ssid:        ssid,
		digestStore: newPairwiseDigestStore(),
		peers:       peers,
		peerManager: &staticPM{self: self},
	}
	var blamed string
	h.onBlamedPeers = func(m map[string]struct{}) {
		for id := range m {
			blamed = id
		}
	}
	// Table only commits to p2; missing p3 for a 3-party sender view.
	digests := map[string][]byte{
		"p2": edgeDigest(ssid, tagR1, sender, "p2", []byte("a")),
	}
	entries := buildSortedEntries(digests)
	root := tableRoot(ssid, tagR1, sender, entries)
	err := h.acceptDigestTable(digestR1, sender, tagR1, entries, root)
	if err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
	if blamed != sender {
		t.Fatalf("want blame %s, got %q", sender, blamed)
	}
}

func TestExpectedPeersForSender3Party(t *testing.T) {
	h := &round1Handler{
		peers: map[string]*peer{
			tss.GetTestID(1): {Peer: message.NewPeer(tss.GetTestID(1))},
			tss.GetTestID(2): {Peer: message.NewPeer(tss.GetTestID(2))},
		},
		peerManager: &staticPM{self: tss.GetTestID(0)},
	}
	got := h.expectedPeersForSender(tss.GetTestID(1))
	want := []string{tss.GetTestID(0), tss.GetTestID(2)}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestStoreBlamedPeersMerge(t *testing.T) {
	s := &Sign{}
	s.storeBlamedPeers(map[string]struct{}{"a": {}})
	s.storeBlamedPeers(map[string]struct{}{"b": {}})
	if _, ok := s.blamedPeers["a"]; !ok {
		t.Fatal("missing a")
	}
	if _, ok := s.blamedPeers["b"]; !ok {
		t.Fatal("missing b")
	}
}

func TestValidateDigestTableRejectsBadDigestLen(t *testing.T) {
	ssid := []byte("ssid")
	sender := "s"
	peers := []string{"p1"}
	short := edgeDigest(ssid, tagR1, sender, "p1", []byte("a"))[:16]
	entries := []*PeerDigestEntry{{PeerId: "p1", Digest: short}}
	root := tableRoot(ssid, tagR1, sender, entries)
	if _, err := ValidateDigestTable(ssid, tagR1, sender, peers, entries, root); err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
}

func TestValidateDigestTableRejectsDuplicatePeer(t *testing.T) {
	ssid := []byte("ssid")
	sender := "s"
	peers := []string{"p1", "p2"}
	d1 := edgeDigest(ssid, tagR1, sender, "p1", []byte("a"))
	d2 := edgeDigest(ssid, tagR1, sender, "p2", []byte("b"))
	// Same length as expectedPeers so validation reaches the duplicate-peer branch.
	entries := []*PeerDigestEntry{
		{PeerId: "p1", Digest: d1},
		{PeerId: "p1", Digest: d2},
	}
	root := tableRoot(ssid, tagR1, sender, entries)
	if _, err := ValidateDigestTable(ssid, tagR1, sender, peers, entries, root); err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
}

func TestValidateDigestTableRejectsMissingPeerInTable(t *testing.T) {
	ssid := []byte("ssid")
	sender := "s"
	peers := []string{"p1", "p2"}
	d1 := edgeDigest(ssid, tagR1, sender, "p1", []byte("a"))
	entries := []*PeerDigestEntry{{PeerId: "p1", Digest: d1}}
	root := tableRoot(ssid, tagR1, sender, entries)
	if _, err := ValidateDigestTable(ssid, tagR1, sender, peers, entries, root); err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
}

func TestValidateDigestTableRejectsUnknownPeer(t *testing.T) {
	ssid := []byte("ssid")
	sender := "s"
	peers := []string{"p1"}
	entries := []*PeerDigestEntry{
		{PeerId: "p2", Digest: edgeDigest(ssid, tagR1, sender, "p2", []byte("a"))},
	}
	root := tableRoot(ssid, tagR1, sender, entries)
	if _, err := ValidateDigestTable(ssid, tagR1, sender, peers, entries, root); err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
}

func TestGateEdgeDigestAcceptsWhenStoreReady(t *testing.T) {
	ssid := []byte("ssid")
	self := "self"
	sender := "peer"
	payload := []byte("opened")
	want := edgeDigest(ssid, tagR2, sender, self, payload)
	h := &round1Handler{
		ssid:        ssid,
		digestStore: newPairwiseDigestStore(),
		peerManager: &staticPM{self: self},
	}
	h.digestStore.SetFinalized(digestR2, sender, map[string][]byte{self: want})
	err := h.gateEdgeDigest(digestR2, sender, self, func() ([]byte, error) {
		return edgeDigest(ssid, tagR2, sender, self, payload), nil
	})
	if err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func TestGateDigestBarrierBlames(t *testing.T) {
	ssid := []byte("ssid")
	self := "self"
	sender := "evil"
	h := &round1Handler{
		ssid:        ssid,
		digestStore: newPairwiseDigestStore(),
		peerManager: &staticPM{self: self},
	}
	var blamed string
	h.onBlamedPeers = func(m map[string]struct{}) {
		for id := range m {
			blamed = id
		}
	}
	err := h.gateEdgeDigest(digestR1, sender, self, func() ([]byte, error) {
		return edgeDigest(ssid, tagR1, sender, self, []byte("x")), nil
	})
	if err != ErrDigestBarrier {
		t.Fatalf("want barrier, got %v", err)
	}
	if blamed != sender {
		t.Fatalf("want blame %s, got %q", sender, blamed)
	}
}

func TestRound1PsiDigestStable(t *testing.T) {
	ssid := []byte("ssid")
	psi := &Round1Msg{Psi: &paillier.EncryptRangeMessage{}}
	d1, err := Round1PsiDigest(ssid, "a", "b", psi)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Round1PsiDigest(ssid, "a", "b", psi)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d1, d2) {
		t.Fatal("Round1PsiDigest not stable")
	}
	if len(d1) != digestLen {
		t.Fatalf("digest len %d", len(d1))
	}
}

func TestRound3PairwiseDigestStable(t *testing.T) {
	ssid := []byte("ssid")
	psi := &paillier.LogStarMessage{}
	d1, err := Round3PairwiseDigest(ssid, "i", "j", psi)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Round3PairwiseDigest(ssid, "i", "j", psi)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d1, d2) {
		t.Fatal("Round3PairwiseDigest not stable")
	}
}

func TestRound2DigestOnDigestTimeoutBlames(t *testing.T) {
	missing := "id-1"
	h := &round2DigestHandler{
		round1Handler: &round1Handler{
			ssid:        []byte("ssid"),
			digestStore: newPairwiseDigestStore(),
			peers: map[string]*peer{
				missing: {Peer: message.NewPeer(missing)},
			},
			peerManager: &staticPM{self: "id-0"},
		},
	}
	var blamed string
	h.onBlamedPeers = func(m map[string]struct{}) {
		for id := range m {
			blamed = id
		}
	}
	h.OnDigestTimeout()
	if blamed != missing {
		t.Fatalf("want blame %s, got %q", missing, blamed)
	}
}

func TestRound3DigestOnDigestTimeoutBlames(t *testing.T) {
	missing := "id-1"
	h := &round3DigestHandler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				ssid:        []byte("ssid"),
				digestStore: newPairwiseDigestStore(),
				peers: map[string]*peer{
					missing: {Peer: message.NewPeer(missing)},
				},
				peerManager: &staticPM{self: "id-0"},
			},
		},
	}
	var blamed string
	h.round1Handler.onBlamedPeers = func(m map[string]struct{}) {
		for id := range m {
			blamed = id
		}
	}
	h.OnDigestTimeout()
	if blamed != missing {
		t.Fatalf("want blame %s, got %q", missing, blamed)
	}
}

func TestRound1DigestNilBodyBlamesSender(t *testing.T) {
	sender := "evil"
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			ssid:        []byte("ssid"),
			digestStore: newPairwiseDigestStore(),
			peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager: &staticPM{self: "self"},
		},
	}
	var blamed string
	h.onBlamedPeers = func(m map[string]struct{}) {
		for id := range m {
			blamed = id
		}
	}
	err := h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round1Digest,
		Body: &Message_Round1Digest{},
	})
	if err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
	if blamed != sender {
		t.Fatalf("want blame %s, got %q", sender, blamed)
	}
}

func TestRound1DigestOnDigestTimeoutBlames(t *testing.T) {
	missing := tss.GetTestID(1)
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			ssid:        []byte("ssid"),
			digestStore: newPairwiseDigestStore(),
			peers: map[string]*peer{
				missing: {Peer: message.NewPeer(missing)},
			},
			peerManager: &staticPM{self: tss.GetTestID(0)},
		},
	}
	var blamed string
	h.onBlamedPeers = func(m map[string]struct{}) {
		for id := range m {
			blamed = id
		}
	}
	h.OnDigestTimeout()
	if blamed != missing {
		t.Fatalf("want blame %s, got %q", missing, blamed)
	}
}

func TestSessionRound2MatchesDigestMissingStoreEntry(t *testing.T) {
	ssid := []byte("ssid")
	self := "id-0"
	sender := "id-1"
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{"other": make([]byte, 32)})

	h := &round1Handler{
		ssid:        ssid,
		digestStore: store,
		peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
		peerManager: &staticPM{self: self},
	}
	if h.sessionRound2MatchesDigest(sender) {
		t.Fatal("expected false when store lacks self edge")
	}
}

func TestPairwiseDigestStoreGetMiss(t *testing.T) {
	store := newPairwiseDigestStore()
	if _, ok := store.Get(digestR2, "sender", "self"); ok {
		t.Fatal("expected miss on empty store")
	}
	store.SetFinalized(digestR2, "sender", map[string][]byte{"peer": make([]byte, 32)})
	if _, ok := store.Get(digestR2, "sender", "self"); ok {
		t.Fatal("expected miss for unknown recipient")
	}
}

func TestValidateDigestTableRejectsNilEntry(t *testing.T) {
	ssid := []byte("ssid")
	sender := "s"
	peers := []string{"p1"}
	entries := []*PeerDigestEntry{nil}
	root := make([]byte, 32)
	if _, err := ValidateDigestTable(ssid, tagR1, sender, peers, entries, root); err != ErrPairwiseDigestTable {
		t.Fatalf("want table err for nil entry, got %v", err)
	}
}
