package sign

import (
	"errors"
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/blame"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

type stubMessageMain struct {
	state   types.MainState
	handler types.Handler
}

func (s *stubMessageMain) AddMessage(string, types.Message) error { return nil }
func (s *stubMessageMain) GetHandler() types.Handler              { return s.handler }
func (s *stubMessageMain) GetState() types.MainState              { return s.state }
func (s *stubMessageMain) Start()                                 {}
func (s *stubMessageMain) Stop()                                  {}

func TestGateEdgeDigestComputeErrorBlames(t *testing.T) {
	ssid := []byte("ssid")
	self := "self"
	sender := "evil"
	h := &round1Handler{
		ssid:        ssid,
		digestStore: newPairwiseDigestStore(),
		peerManager: &staticPM{self: self},
	}
	var blamed string
	h.onBlame = func(c cggmp.BlameContribution) { m := c.Union(); 
		for id := range m {
			blamed = id
		}
	}
	want := edgeDigest(ssid, tagR2, sender, self, []byte("x"))
	h.digestStore.SetFinalized(digestR2, sender, map[string][]byte{self: want})

	computeErr := errors.New("compute failed")
	err := h.gateEdgeDigest(digestR2, sender, self, func() ([]byte, error) {
		return nil, computeErr
	})
	if !errors.Is(err, computeErr) {
		t.Fatalf("want compute err, got %v", err)
	}
	if blamed != sender {
		t.Fatalf("want blame %s, got %q", sender, blamed)
	}
}

func TestBlameSenderNoCallbackDoesNotPanic(t *testing.T) {
	h := &round1Handler{onBlame: nil}
	h.blameSender("peer")
}

func TestSessionRound2MatchesDigestNilStore(t *testing.T) {
	h := &round1Handler{
		digestStore: nil,
		peerManager: &staticPM{self: "id-0"},
	}
	if !h.sessionRound2MatchesDigest("id-1") {
		t.Fatal("nil store should skip check")
	}
}

func TestSessionRound2MatchesDigestMissingPeer(t *testing.T) {
	ssid := []byte("ssid")
	self := "id-0"
	sender := "id-1"
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: make([]byte, 32)})

	h := &round1Handler{
		ssid:        ssid,
		digestStore: store,
		peers:       map[string]*peer{},
		peerManager: &staticPM{self: self},
	}
	if h.sessionRound2MatchesDigest(sender) {
		t.Fatal("expected false when sender peer missing")
	}
}

func TestSessionRound2MatchesDigestMissingRound2Msg(t *testing.T) {
	ssid := []byte("ssid")
	self := "id-0"
	sender := "id-1"
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: make([]byte, 32)})

	h := &round1Handler{
		ssid:        ssid,
		digestStore: store,
		peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
		peerManager: &staticPM{self: self},
	}
	if h.sessionRound2MatchesDigest(sender) {
		t.Fatal("expected false when Round2 message missing")
	}
}

func TestSessionRound2MatchesDigestNilRound2Body(t *testing.T) {
	ssid := []byte("ssid")
	self := "id-0"
	sender := "id-1"
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: make([]byte, 32)})

	peerNode := &peer{Peer: message.NewPeer(sender)}
	round2Msg := &Message{Id: sender, Type: Type_Round2, Body: &Message_Round2{}}
	if err := peerNode.AddMessage(round2Msg); err != nil {
		t.Fatal(err)
	}

	h := &round1Handler{
		ssid:        ssid,
		digestStore: store,
		peers:       map[string]*peer{sender: peerNode},
		peerManager: &staticPM{self: self},
	}
	if h.sessionRound2MatchesDigest(sender) {
		t.Fatal("expected false when Round2 body is nil")
	}
}

func TestRound1DigestFinalizeRequiresPending(t *testing.T) {
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			peers:       map[string]*peer{"p1": {Peer: message.NewPeer("p1")}},
			peerManager: &staticPM{self: "self"},
		},
		pendingRound1: map[string]*Message{},
	}
	_, err := h.Finalize(log.New())
	if err == nil {
		t.Fatal("expected error for empty pendingRound1")
	}
}

func TestBroadcastRound1DigestNilMsg(t *testing.T) {
	h := &round1DigestHandler{digestMsg: nil}
	h.broadcastRound1Digest()
}

func TestRound2DigestNilBodyBlamesSender(t *testing.T) {
	sender := "evil"
	h := &round2DigestHandler{
		round1Handler: &round1Handler{
			ssid:        []byte("ssid"),
			digestStore: newPairwiseDigestStore(),
			peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager: &staticPM{self: "self"},
		},
	}
	var blamed string
	h.onBlame = func(c cggmp.BlameContribution) { m := c.Union(); 
		for id := range m {
			blamed = id
		}
	}
	err := h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round2Digest,
		Body: &Message_Round2Digest{},
	})
	if err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
	if blamed != sender {
		t.Fatalf("want blame %s, got %q", sender, blamed)
	}
}

func TestRound2DigestInvalidGammaBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r2-gamma-bad")
	self := "id-0"
	sender := "id-1"
	entries, root := commitDigestTable(ssid, tagR2, sender, map[string][]byte{
		self: edgeDigest(ssid, tagR2, sender, self, []byte("x")),
	})

	sign := &Sign{}
	h := &round2DigestHandler{
		round1Handler: &round1Handler{
			ssid:          ssid,
			digestStore:   newPairwiseDigestStore(),
			peers:         map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager:   &staticPM{self: self},
			onBlame: sign.storeBlame,
		},
	}
	err := h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round2Digest,
		Body: &Message_Round2Digest{
			Round2Digest: &Round2DigestMsg{
				Gamma:     &pt.EcPointMessage{Curve: 999},
				ToPeer:    entries,
				TableRoot: root,
			},
		},
	})
	if err == nil {
		t.Fatal("expected ToPoint error")
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestRound2DigestFinalizeMissingRound2(t *testing.T) {
	h := &round2DigestHandler{
		round1Handler: &round1Handler{
			peers: map[string]*peer{
				"p1": {Peer: message.NewPeer("p1"), round1Data: &round1Data{}},
			},
			peerManager: &staticPM{self: "self"},
		},
	}
	_, err := h.Finalize(log.New())
	if err == nil {
		t.Fatal("expected missing round2 message error")
	}
}

func TestRound3DigestNilBodyBlamesSender(t *testing.T) {
	sender := "evil"
	h := &round3DigestHandler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				ssid:        []byte("ssid"),
				digestStore: newPairwiseDigestStore(),
				peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
				peerManager: &staticPM{self: "self"},
			},
		},
	}
	var blamed string
	h.onBlame = func(c cggmp.BlameContribution) { m := c.Union(); 
		for id := range m {
			blamed = id
		}
	}
	err := h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round3Digest,
		Body: &Message_Round3Digest{},
	})
	if err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
	if blamed != sender {
		t.Fatalf("want blame %s, got %q", sender, blamed)
	}
}

func TestRound3DigestInvalidBigDeltaBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r3-bd-bad")
	self := "id-0"
	sender := "id-1"
	entries, root := commitDigestTable(ssid, tagR3, sender, map[string][]byte{
		self: edgeDigest(ssid, tagR3, sender, self, []byte("x")),
	})

	sign := &Sign{}
	h := &round3DigestHandler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				ssid:          ssid,
				digestStore:   newPairwiseDigestStore(),
				peers:         map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
				peerManager:   &staticPM{self: self},
				onBlame: sign.storeBlame,
			},
		},
	}
	err := h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round3Digest,
		Body: &Message_Round3Digest{
			Round3Digest: &Round3DigestMsg{
				Delta:     "42",
				BigDelta:  &pt.EcPointMessage{Curve: 999},
				ToPeer:    entries,
				TableRoot: root,
			},
		},
	})
	if err == nil {
		t.Fatal("expected ToPoint error")
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestRound1PsiDigestNilMessage(t *testing.T) {
	d, err := Round1PsiDigest([]byte("ssid"), "a", "b", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(d) != digestLen {
		t.Fatalf("digest len %d", len(d))
	}
}

func TestRound2PairwiseDigestNilMessage(t *testing.T) {
	if _, err := Round2PairwiseDigest([]byte("ssid"), "a", "b", nil); err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
}

func TestRound3PairwiseDigestNilMessage(t *testing.T) {
	d, err := Round3PairwiseDigest([]byte("ssid"), "a", "b", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(d) != digestLen {
		t.Fatalf("digest len %d", len(d))
	}
}

func TestRound1PsiEquivocationBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r1-psi-eq")
	self := "id-0"
	sender := "id-1"
	psiCommitted := &paillierzkproof.EncryptRangeMessage{}
	psiRevealed := &paillierzkproof.EncryptRangeMessage{S: []byte{0x01}}

	want, err := Round1PsiDigest(ssid, sender, self, psiCommitted)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR1, sender, map[string][]byte{self: want})

	kBytes := []byte("k")
	gBytes := []byte("g")
	sign := &Sign{}
	h := &round1Handler{
		ssid:        ssid,
		digestStore: store,
		peers: map[string]*peer{
			sender: {
				Peer:                  message.NewPeer(sender),
				digestKCiphertext:     append([]byte(nil), kBytes...),
				digestGammaCiphertext: append([]byte(nil), gBytes...),
			},
		},
		peerManager:   &staticPM{self: self},
		onBlame: sign.storeBlame,
	}
	err = h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round1,
		Body: &Message_Round1{
			Round1: &Round1Msg{
				KCiphertext:     append([]byte(nil), kBytes...),
				GammaCiphertext: append([]byte(nil), gBytes...),
				Psi:             psiRevealed,
			},
		},
	})
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

func TestRound1GammaCiphertextMismatchBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r1-gamma")
	self := "id-0"
	sender := "id-1"
	psi := &paillierzkproof.EncryptRangeMessage{}
	want, err := Round1PsiDigest(ssid, sender, self, psi)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR1, sender, map[string][]byte{self: want})

	kBytes := []byte("same-k")
	sign := &Sign{}
	h := &round1Handler{
		ssid:        ssid,
		digestStore: store,
		peers: map[string]*peer{
			sender: {
				Peer:                  message.NewPeer(sender),
				digestKCiphertext:     append([]byte(nil), kBytes...),
				digestGammaCiphertext: []byte("digest-g"),
			},
		},
		peerManager:   &staticPM{self: self},
		onBlame: sign.storeBlame,
	}
	err = h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round1,
		Body: &Message_Round1{
			Round1: &Round1Msg{
				KCiphertext:     append([]byte(nil), kBytes...),
				GammaCiphertext: []byte("reveal-g"),
				Psi:             psi,
			},
		},
	})
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

func TestRound2InvalidPsihatVerifyBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r2-psihat")
	self := "id-0"
	sender := "id-1"
	gamma := big.NewInt(7)
	Gamma := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), gamma)
	gammaMsg, err := Gamma.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	kCipher, _, err := errPaillierKeyA.EncryptWithOutputSalt(big.NewInt(5))
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, dBytes, fBytes, psiProof, err := cggmp.MtaWithProofAff_g(ssid, errPedZKB, errPaillierKeyA, kCipher.Bytes(), gamma, Gamma)
	if err != nil {
		t.Fatal(err)
	}
	bkShare := big.NewInt(3)
	bkPartial := errTestG.ScalarMult(bkShare)
	_, _, _, _, dhatBytes, fhatBytes, psihatProof, err := cggmp.MtaWithProofAff_g(ssid, errPedZKB, errPaillierKeyA, kCipher.Bytes(), bkShare, bkPartial)
	if err != nil {
		t.Fatal(err)
	}
	r2 := &Round2Msg{
		D:      dBytes,
		F:      fBytes.Bytes(),
		Dhat:   dhatBytes,
		Fhat:   fhatBytes.Bytes(),
		Psi:    psiProof,
		Psihat: &paillierzkproof.PaillierAffAndGroupRangeMessage{S: []byte{0xff}},
		Gamma:  gammaMsg,
	}
	want, err := Round2PairwiseDigest(ssid, sender, self, r2)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: want})

	sign := &Sign{}
	peerNode := &peer{
		Peer:            message.NewPeer(sender),
		para:            errPedZKB,
		ssidWithBk:      ssid,
		digestGamma:     Gamma,
		partialPubKey:   errTestPublicKey,
		bkcoefficient:   big.NewInt(1),
		round1Data:      &round1Data{kCiphertext: kCipher},
	}
	h := &round2Handler{
		round1Handler: &round1Handler{
			ssid:            ssid,
			digestStore:     store,
			peers:           map[string]*peer{sender: peerNode},
			peerManager:     &staticPM{self: self},
			own:             &peer{para: errPedZKA, ssidWithBk: ssid},
			paillierKey:     errPaillierKeyA,
			kCiphertext:     kCipher,
			bkpartialPubKey: errTestPublicKey,
			onBlame: sign.storeBlame,
		},
	}
	// Restore valid Psihat for digest, tamper only in opened message.
	r2.Psihat = psihatProof
	want, err = Round2PairwiseDigest(ssid, sender, self, r2)
	if err != nil {
		t.Fatal(err)
	}
	store.SetFinalized(digestR2, sender, map[string][]byte{self: want})
	r2.Psihat = &paillierzkproof.PaillierAffAndGroupRangeMessage{S: []byte{0xff}}

	err = h.HandleMessage(log.New(), &Message{Id: sender, Type: Type_Round2, Body: &Message_Round2{Round2: r2}})
	if err == nil {
		t.Fatal("expected Psihat verify error")
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed after invalid Psihat", sender)
	}
}

func TestRound2InvalidPsipaiVerifyBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r2-psipai")
	self := "id-0"
	sender := "id-1"
	gamma := big.NewInt(7)
	mu := big.NewInt(2)
	Gamma := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), gamma)
	gammaMsg, err := Gamma.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	kCipher, _, err := errPaillierKeyA.EncryptWithOutputSalt(big.NewInt(5))
	if err != nil {
		t.Fatal(err)
	}
	gCipher, _, err := errPaillierKeyA.EncryptWithOutputSalt(gamma)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, dBytes, fBytes, psiProof, err := cggmp.MtaWithProofAff_g(ssid, errPedZKB, errPaillierKeyA, kCipher.Bytes(), gamma, Gamma)
	if err != nil {
		t.Fatal(err)
	}
	bkShare := big.NewInt(3)
	bkPartial := errTestG.ScalarMult(bkShare)
	_, _, _, _, dhatBytes, fhatBytes, psihatProof, err := cggmp.MtaWithProofAff_g(ssid, errPedZKB, errPaillierKeyA, kCipher.Bytes(), bkShare, bkPartial)
	if err != nil {
		t.Fatal(err)
	}
	psipaiProof, err := paillierzkproof.NewKnowExponentAndPaillierEncryption(parameter, ssid, gamma, mu, gCipher, errPaillierKeyA.GetN(), errPedZKB, Gamma, errTestG)
	if err != nil {
		t.Fatal(err)
	}
	r2 := &Round2Msg{
		D:      dBytes,
		F:      fBytes.Bytes(),
		Dhat:   dhatBytes,
		Fhat:   fhatBytes.Bytes(),
		Psi:    psiProof,
		Psihat: psihatProof,
		Psipai: psipaiProof,
		Gamma:  gammaMsg,
	}
	want, err := Round2PairwiseDigest(ssid, sender, self, r2)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: want})

	sign := &Sign{}
	peerNode := &peer{
		Peer:            message.NewPeer(sender),
		para:            errPedZKB,
		ssidWithBk:      ssid,
		digestGamma:     Gamma,
		partialPubKey:   errTestPublicKey,
		bkcoefficient:   big.NewInt(1),
		round1Data:      &round1Data{kCiphertext: kCipher, gammaCiphertext: gCipher},
	}
	h := &round2Handler{
		round1Handler: &round1Handler{
			ssid:            ssid,
			digestStore:     store,
			peers:           map[string]*peer{sender: peerNode},
			peerManager:     &staticPM{self: self},
			own:             &peer{para: errPedZKA, ssidWithBk: ssid},
			paillierKey:     errPaillierKeyA,
			kCiphertext:     kCipher,
			bkpartialPubKey: errTestPublicKey,
			onBlame: sign.storeBlame,
		},
	}
	r2.Psipai = &paillierzkproof.LogStarMessage{S: []byte{0xff}}
	err = h.HandleMessage(log.New(), &Message{Id: sender, Type: Type_Round2, Body: &Message_Round2{Round2: r2}})
	if err == nil {
		t.Fatal("expected Psipai verify error")
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed after invalid Psipai", sender)
	}
}

func TestRound2InvalidGammaToPointBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r2-tp")
	self := "id-0"
	sender := "id-1"
	sign := &Sign{}
	h := &round2Handler{
		round1Handler: &round1Handler{
			ssid:          ssid,
			digestStore:   newPairwiseDigestStore(),
			peers:         map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager:   &staticPM{self: self},
			onBlame: sign.storeBlame,
		},
	}
	err := h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round2,
		Body: &Message_Round2{
			Round2: &Round2Msg{Gamma: &pt.EcPointMessage{Curve: 999}},
		},
	})
	if err == nil {
		t.Fatal("expected ToPoint error")
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestRound2DigestGammaNilBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r2-nil-gamma")
	self := "id-0"
	sender := "id-1"
	r2 := &Round2Msg{D: []byte{1}, F: []byte{2}, Dhat: []byte{3}, Fhat: []byte{4}}
	want, err := Round2PairwiseDigest(ssid, sender, self, r2)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: want})

	gammaMsg, err := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(1)).ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	r2.Gamma = gammaMsg

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
	err = h.HandleMessage(log.New(), &Message{Id: sender, Type: Type_Round2, Body: &Message_Round2{Round2: r2}})
	if err != ErrPairwiseDigestMismatch {
		t.Fatalf("want mismatch for nil digestGamma, got %v", err)
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestRound3InvalidDeltaParseBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r3-parse")
	self := "id-0"
	sender := "id-1"
	psi := &paillierzkproof.LogStarMessage{}
	want, err := Round3PairwiseDigest(ssid, sender, self, psi)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR3, sender, map[string][]byte{self: want})

	bigDelta := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(3))
	bigDeltaMsg, err := bigDelta.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	kCipher, _, err := errPaillierKeyB.EncryptWithOutputSalt(big.NewInt(2))
	if err != nil {
		t.Fatal(err)
	}

	sign := &Sign{}
	peerNode := &peer{
		Peer:           message.NewPeer(sender),
		para:           errPedZKB,
		ssidWithBk:     ssid,
		digestDelta:    "42",
		digestBigDelta: bigDelta,
		round1Data:     &round1Data{kCiphertext: kCipher},
	}
	h := &round3Handler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				ssid:          ssid,
				digestStore:   store,
				peers:         map[string]*peer{sender: peerNode},
				peerManager:   &staticPM{self: self},
				own:           &peer{para: errPedZKA, ssidWithBk: ssid},
				sumGamma:      errTestG,
				onBlame: sign.storeBlame,
			},
		},
	}
	err = h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round3,
		Body: &Message_Round3{
			Round3: &Round3Msg{
				Delta:        "not-a-valid-int",
				BigDelta:     bigDeltaMsg,
				Psidoublepai: psi,
			},
		},
	})
	if err == nil {
		t.Fatal("expected parse error")
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestRound3InvalidBigDeltaToPointBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r3-tp")
	self := "id-0"
	sender := "id-1"
	sign := &Sign{}
	h := &round3Handler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				ssid:          ssid,
				digestStore:   newPairwiseDigestStore(),
				peers:         map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
				peerManager:   &staticPM{self: self},
				own:           &peer{para: errPedZKA},
				onBlame: sign.storeBlame,
			},
		},
	}
	err := h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round3,
		Body: &Message_Round3{
			Round3: &Round3Msg{BigDelta: &pt.EcPointMessage{Curve: 999}},
		},
	})
	if err == nil {
		t.Fatal("expected ToPoint error")
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestGetBlamedPeersReturnsStoredCopy(t *testing.T) {
	sign := &Sign{
		hasBlameSnapshot: true,
		blameResult: blame.Result{
			Confirmed: map[string]struct{}{"a": {}},
		},
		MessageMain: &stubMessageMain{state: types.StateFailed},
	}
	blamed, err := sign.GetBlamedPeers()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed["a"]; !ok {
		t.Fatal("missing blamed peer")
	}
	blamed["b"] = struct{}{}
	sign.blamedMu.RLock()
	_, leaked := sign.blameResult.Confirmed["b"]
	if !leaked {
		_, leaked = sign.blameResult.Suspect["b"]
	}
	sign.blamedMu.RUnlock()
	if leaked {
		t.Fatal("GetBlamedPeers should return a copy")
	}
}

func TestGetBlamedPeersEmptyWhenNoSnapshot(t *testing.T) {
	sign := &Sign{
		abortCollector: cggmp.NewAbortMsgCollector[*Message](),
		MessageMain:    &stubMessageMain{state: types.StateFailed, handler: &round4Handler{}},
	}
	blamed, err := sign.GetBlamedPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed) != 0 {
		t.Fatalf("want empty map, got %v", blamed)
	}
}

func TestGetBlamedPeersFallbackUnknownHandler(t *testing.T) {
	collector := cggmp.NewAbortMsgCollector[*Message]()
	collector.Record(&Message{Id: "x", Type: Type_Err1})
	sign := &Sign{
		abortCollector: collector,
		MessageMain:    &stubMessageMain{state: types.StateFailed, handler: &round1Handler{}},
	}
	blamed, err := sign.GetBlamedPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed) != 0 {
		t.Fatalf("want empty map for unknown handler, got %v", blamed)
	}
}
