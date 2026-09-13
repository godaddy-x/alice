package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
)

func TestSessionRound2MatchesDigest(t *testing.T) {
	ssid := []byte("ssid")
	self := "id-0"
	sender := "id-1"
	r2 := &Round2Msg{
		D:    []byte{1, 2, 3},
		F:    []byte{4, 5},
		Dhat: []byte{6},
		Fhat: []byte{7},
	}
	want, err := Round2PairwiseDigest(ssid, sender, self, r2)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: want})

	peerNode := &peer{Peer: message.NewPeer(sender)}
	round2Msg := &Message{
		Id:   sender,
		Type: Type_Round2,
		Body: &Message_Round2{Round2: r2},
	}
	if err := peerNode.AddMessage(round2Msg); err != nil {
		t.Fatal(err)
	}

	h := &round1Handler{
		ssid:        ssid,
		digestStore: store,
		peers:       map[string]*peer{sender: peerNode},
		peerManager: &staticPM{self: self},
	}
	if !h.sessionRound2MatchesDigest(sender) {
		t.Fatal("expected digest match")
	}

	tampered := &Round2Msg{
		D:    []byte{9},
		F:    r2.GetF(),
		Dhat: r2.GetDhat(),
		Fhat: r2.GetFhat(),
	}
	tamperedMsg := &Message{
		Id:   sender,
		Type: Type_Round2,
		Body: &Message_Round2{Round2: tampered},
	}
	peerTampered := &peer{Peer: message.NewPeer(sender)}
	if err := peerTampered.AddMessage(tamperedMsg); err != nil {
		t.Fatal(err)
	}
	h.peers[sender] = peerTampered
	if h.sessionRound2MatchesDigest(sender) {
		t.Fatal("expected digest mismatch")
	}
}

func TestSessionRound2MatchesDigestSkipsWithoutStore(t *testing.T) {
	h := &round1Handler{
		digestStore: newPairwiseDigestStore(),
		peerManager: &staticPM{self: "id-0"},
	}
	if !h.sessionRound2MatchesDigest("id-1") {
		t.Fatal("should skip check when no R2 tables")
	}
}

func TestRound2EquivocationBlamesSender(t *testing.T) {
	ssid := []byte("ssid")
	self := "id-0"
	sender := "id-1"
	committed := &Round2Msg{
		D:    []byte{1},
		F:    []byte{2},
		Dhat: []byte{3},
		Fhat: []byte{4},
	}
	want, err := Round2PairwiseDigest(ssid, sender, self, committed)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: want})

	opened := &Round2Msg{
		D:    []byte{9},
		F:    committed.GetF(),
		Dhat: committed.GetDhat(),
		Fhat: committed.GetFhat(),
	}
	gammaPt := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(7))
	gammaMsg, err := gammaPt.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	committed.Gamma = gammaMsg
	opened.Gamma = gammaMsg

	msg := &Message{
		Id:   sender,
		Type: Type_Round2,
		Body: &Message_Round2{Round2: opened},
	}

	sign := &Sign{}
	h := &round2Handler{
		round1Handler: &round1Handler{
			ssid:          ssid,
			digestStore:   store,
			peers:         map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager:   &staticPM{self: self},
			onBlame: sign.storeBlame,
		},
	}
	err = h.HandleMessage(log.New(), msg)
	if err != ErrPairwiseDigestMismatch {
		t.Fatalf("want mismatch, got %v", err)
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestEchoConflictRound1DigestBlamesAuthor(t *testing.T) {
	var blamed string
	sign := &Sign{}
	onConflict := func(authorID string) {
		sign.storeBlame(cggmp.BlameContributionFromConfirmed(map[string]struct{}{authorID: {}}))
		blamed = authorID
	}

	pm := &threePartyPM{self: tss.GetTestID(0)}
	author := tss.GetTestID(1)

	digestA := round1DigestEchoMsg(author, []byte("k-a"), []byte("g-a"))
	digestB := round1DigestEchoMsg(author, []byte("k-b"), []byte("g-a"))

	echo := message.NewEchoMsgMain(nil, pm)
	echo.SetOnConflict(onConflict)

	if err := echo.AddMessage(tss.GetTestID(2), digestA); err != nil {
		t.Fatalf("first echo: %v", err)
	}
	err := echo.AddMessage(tss.GetTestID(0), digestB)
	if err != message.ErrDifferentHash {
		t.Fatalf("want ErrDifferentHash, got %v", err)
	}
	if blamed != author {
		t.Fatalf("want blame %s, got %q", author, blamed)
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[author]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatal("storeBlame should record echo author")
	}
}
