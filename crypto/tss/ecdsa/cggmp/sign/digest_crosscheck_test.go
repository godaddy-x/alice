package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

func TestRound1CiphertextCrossCheckBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r1-xcheck")
	self := "id-0"
	sender := "id-1"
	psi := &paillier.EncryptRangeMessage{}

	want, err := Round1PsiDigest(ssid, sender, self, psi)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR1, sender, map[string][]byte{self: want})

	sign := &Sign{}
	peerNode := &peer{
		Peer:                  message.NewPeer(sender),
		digestKCiphertext:     []byte("digest-k"),
		digestGammaCiphertext: []byte("digest-g"),
	}
	h := &round1Handler{
		ssid:          ssid,
		digestStore:   store,
		peers:         map[string]*peer{sender: peerNode},
		peerManager:   &staticPM{self: self},
		own:           &peer{para: errPedZKA},
		onBlamedPeers: sign.storeBlamedPeers,
	}
	msg := &Message{
		Id:   sender,
		Type: Type_Round1,
		Body: &Message_Round1{
			Round1: &Round1Msg{
				KCiphertext:     []byte("reveal-k"),
				GammaCiphertext: []byte("digest-g"),
				Psi:             psi,
			},
		},
	}
	err = h.HandleMessage(log.New(), msg)
	if err != ErrPairwiseDigestMismatch {
		t.Fatalf("want mismatch, got %v", err)
	}
	sign.blamedMu.RLock()
	_, ok := sign.blamedPeers[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestRound2GammaCrossCheckBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r2-gamma")
	self := "id-0"
	sender := "id-1"

	gammaDigest := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(7))
	gammaReveal := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(8))
	gammaRevealMsg, err := gammaReveal.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}

	r2 := &Round2Msg{
		D:    []byte{1},
		F:    []byte{2},
		Dhat: []byte{3},
		Fhat: []byte{4},
	}
	want, err := Round2PairwiseDigest(ssid, sender, self, r2)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: want})

	sign := &Sign{}
	peerNode := &peer{
		Peer:        message.NewPeer(sender),
		digestGamma: gammaDigest,
	}
	h := &round2Handler{
		round1Handler: &round1Handler{
			ssid:          ssid,
			digestStore:   store,
			peers:         map[string]*peer{sender: peerNode},
			peerManager:   &staticPM{self: self},
			onBlamedPeers: sign.storeBlamedPeers,
		},
	}
	msg := &Message{
		Id:   sender,
		Type: Type_Round2,
		Body: &Message_Round2{
			Round2: &Round2Msg{
				D:     r2.GetD(),
				F:     r2.GetF(),
				Dhat:  r2.GetDhat(),
				Fhat:  r2.GetFhat(),
				Gamma: gammaRevealMsg,
			},
		},
	}
	err = h.HandleMessage(log.New(), msg)
	if err != ErrPairwiseDigestMismatch {
		t.Fatalf("want mismatch, got %v", err)
	}
	sign.blamedMu.RLock()
	_, ok := sign.blamedPeers[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestRound3DeltaCrossCheckBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r3-delta")
	self := "id-0"
	sender := "id-1"

	psi := &paillier.LogStarMessage{}
	want, err := Round3PairwiseDigest(ssid, sender, self, psi)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR3, sender, map[string][]byte{self: want})

	bigDeltaDigest := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(3))
	bigDeltaReveal := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(4))
	bigDeltaRevealMsg, err := bigDeltaReveal.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}

	sign := &Sign{}
	peerNode := &peer{
		Peer:            message.NewPeer(sender),
		digestDelta:     "42",
		digestBigDelta:  bigDeltaDigest,
	}
	h := &round3Handler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				ssid:          ssid,
				digestStore:   store,
				peers:         map[string]*peer{sender: peerNode},
				peerManager:   &staticPM{self: self},
				own:           &peer{para: errPedZKA},
				sumGamma:      errTestG,
				onBlamedPeers: sign.storeBlamedPeers,
			},
		},
	}
	msg := &Message{
		Id:   sender,
		Type: Type_Round3,
		Body: &Message_Round3{
			Round3: &Round3Msg{
				Delta:        "43",
				BigDelta:     bigDeltaRevealMsg,
				Psidoublepai: psi,
			},
		},
	}
	err = h.HandleMessage(log.New(), msg)
	if err != ErrPairwiseDigestMismatch {
		t.Fatalf("want mismatch, got %v", err)
	}
	sign.blamedMu.RLock()
	_, ok := sign.blamedPeers[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestEchoConflictRound2DigestBlamesAuthor(t *testing.T) {
	var blamed string
	sign := &Sign{}
	onConflict := func(authorID string) {
		sign.storeBlamedPeers(map[string]struct{}{authorID: {}})
		blamed = authorID
	}

	pm := &threePartyPM{self: tss.GetTestID(0)}
	author := tss.GetTestID(1)
	gammaA := &pt.EcPointMessage{Curve: 1, X: []byte("gx-a"), Y: []byte("gy-a")}
	gammaB := &pt.EcPointMessage{Curve: 1, X: []byte("gx-b"), Y: []byte("gy-b")}

	digestA := round2DigestEchoMsg(author, gammaA, []byte("root-a"))
	digestB := round2DigestEchoMsg(author, gammaB, []byte("root-a"))

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
	_, ok := sign.blamedPeers[author]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatal("storeBlamedPeers should record echo author")
	}
}

func TestEchoConflictRound3DigestBlamesAuthor(t *testing.T) {
	var blamed string
	sign := &Sign{}
	onConflict := func(authorID string) {
		sign.storeBlamedPeers(map[string]struct{}{authorID: {}})
		blamed = authorID
	}

	pm := &threePartyPM{self: tss.GetTestID(0)}
	author := tss.GetTestID(1)
	bdA := &pt.EcPointMessage{Curve: 1, X: []byte("dx-a"), Y: []byte("dy-a")}
	bdB := &pt.EcPointMessage{Curve: 1, X: []byte("dx-b"), Y: []byte("dy-b")}

	digestA := round3DigestEchoMsg(author, "42", bdA, []byte("root-a"))
	digestB := round3DigestEchoMsg(author, "42", bdB, []byte("root-a"))

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
	_, ok := sign.blamedPeers[author]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatal("storeBlamedPeers should record echo author")
	}
}
