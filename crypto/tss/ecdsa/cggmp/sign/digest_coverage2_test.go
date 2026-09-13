package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

type recordPM struct {
	staticPM
	sent []string
}

func (p *recordPM) MustSend(id string, _ interface{}) {
	p.sent = append(p.sent, id)
}

func TestRound1DigestHandleMessagePeerNotFound(t *testing.T) {
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			peers:       map[string]*peer{},
			peerManager: &staticPM{self: "self"},
		},
	}
	err := h.HandleMessage(log.New(), &Message{Id: "missing", Type: Type_Round1Digest})
	if err != tss.ErrPeerNotFound {
		t.Fatalf("want ErrPeerNotFound, got %v", err)
	}
}

func TestRound2DigestHandleMessagePeerNotFound(t *testing.T) {
	h := &round2DigestHandler{
		round1Handler: &round1Handler{
			peers:       map[string]*peer{},
			peerManager: &staticPM{self: "self"},
		},
	}
	err := h.HandleMessage(log.New(), &Message{Id: "missing", Type: Type_Round2Digest})
	if err != tss.ErrPeerNotFound {
		t.Fatalf("want ErrPeerNotFound, got %v", err)
	}
}

func TestRound3DigestHandleMessagePeerNotFound(t *testing.T) {
	h := &round3DigestHandler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				peers:       map[string]*peer{},
				peerManager: &staticPM{self: "self"},
			},
		},
	}
	err := h.HandleMessage(log.New(), &Message{Id: "missing", Type: Type_Round3Digest})
	if err != tss.ErrPeerNotFound {
		t.Fatalf("want ErrPeerNotFound, got %v", err)
	}
}

func TestRound1DigestHandleMessageInvalidTableBlames(t *testing.T) {
	ssid := []byte("ssid-r1-table")
	self := "id-0"
	sender := "id-1"
	sign := &Sign{}
	h := &round1DigestHandler{
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
		Type: Type_Round1Digest,
		Body: &Message_Round1Digest{
			Round1Digest: &Round1DigestMsg{
				KCiphertext:     []byte("k"),
				GammaCiphertext: []byte("g"),
				ToPeer:          []*PeerDigestEntry{},
				TableRoot:       make([]byte, 32),
			},
		},
	})
	if err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestRound1DigestHandleMessageSuccess(t *testing.T) {
	ssid := []byte("ssid-r1-ok")
	self := "id-0"
	sender := "id-1"
	psi := &paillierzkproof.EncryptRangeMessage{}
	want, err := Round1PsiDigest(ssid, sender, self, psi)
	if err != nil {
		t.Fatal(err)
	}
	entries, root := commitDigestTable(ssid, tagR1, sender, map[string][]byte{self: want})

	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			ssid:        ssid,
			digestStore: newPairwiseDigestStore(),
			peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager: &staticPM{self: self},
		},
	}
	err = h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round1Digest,
		Body: &Message_Round1Digest{
			Round1Digest: &Round1DigestMsg{
				KCiphertext:     []byte("k"),
				GammaCiphertext: []byte("g"),
				ToPeer:          entries,
				TableRoot:       root,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := h.peers[sender]
	if !bytesEqual(peer.digestKCiphertext, []byte("k")) {
		t.Fatal("digest k not stashed")
	}
	if _, ok := h.digestStore.Get(digestR1, sender, self); !ok {
		t.Fatal("digest table not finalized")
	}
}

func TestPrepareRound1DigestAndFinalizeSuccess(t *testing.T) {
	ssid := []byte("ssid-prepare")
	self := "self"
	peerNode := newErrTestPeer("p1", ssid, errPedZKB)
	k := big.NewInt(5)
	rho := big.NewInt(3)
	kCipher, _, err := errPaillierKeyA.EncryptWithOutputSalt(k)
	if err != nil {
		t.Fatal(err)
	}
	gCipher, _, err := errPaillierKeyA.EncryptWithOutputSalt(big.NewInt(7))
	if err != nil {
		t.Fatal(err)
	}
	pm := &recordPM{staticPM: staticPM{self: self}}
	h := &round1DigestHandler{
		round1Handler: &round1Handler{
			ssid:            ssid,
			k:               k,
			rho:             rho,
			kCiphertext:     kCipher,
			gammaCiphertext: gCipher,
			paillierKey:     errPaillierKeyA,
			peers:           map[string]*peer{"p1": peerNode},
			peerManager:     pm,
		},
	}
	if err := h.prepareRound1Digest(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if h.digestMsg == nil || len(h.pendingRound1) != 1 {
		t.Fatal("expected pending Round1 and digestMsg")
	}
	next, err := h.Finalize(log.New())
	if err != nil {
		t.Fatal(err)
	}
	if next != h.round1Handler {
		t.Fatal("expected round1Handler after digest Finalize")
	}
	if len(pm.sent) != 1 || pm.sent[0] != "p1" {
		t.Fatalf("expected pending Round1 sent, got %v", pm.sent)
	}
}

func TestBuildRound2DigestAndBroadcastError(t *testing.T) {
	ssid := []byte("ssid-r2-build")
	self := "self"
	gammaMsg, err := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(3)).ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	h := &round1Handler{
		ssid: ssid,
		peers: map[string]*peer{
			"p1": {
				Peer: message.NewPeer("p1"),
				round1Data: &round1Data{
					round2Msg: &Message{Id: self, Type: Type_Round2, Body: &Message_Round2{}},
				},
			},
		},
		peerManager: &staticPM{self: self},
	}
	if err := h.buildRound2DigestAndBroadcast(gammaMsg); err == nil {
		t.Fatal("expected Round2PairwiseDigest error")
	}
}

func TestBuildRound3DigestAndBroadcastSuccess(t *testing.T) {
	ssid := []byte("ssid-r3-build-ok")
	self := "self"
	delta := big.NewInt(42)
	deltaMsg, err := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(2)).ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	pm := &recordPM{staticPM: staticPM{self: self}}
	psi := &paillierzkproof.LogStarMessage{}
	h := &round2Handler{
		round1Handler: &round1Handler{
			ssid:        ssid,
			peerManager: pm,
			peers: map[string]*peer{
				"p1": {Peer: message.NewPeer("p1")},
			},
		},
	}
	pending := map[string]*Message{
		"p1": {
			Id:   self,
			Type: Type_Round3,
			Body: &Message_Round3{Round3: &Round3Msg{Psidoublepai: psi}},
		},
	}
	if err := h.buildRound3DigestAndBroadcast(delta, deltaMsg, pending); err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	if len(pm.sent) != 1 || pm.sent[0] != "p1" {
		t.Fatalf("expected digest broadcast to peer, got %v", pm.sent)
	}
}

func TestRound2DigestFinalizeSuccess(t *testing.T) {
	pm := &recordPM{staticPM: staticPM{self: "self"}}
	round2Msg := &Message{Id: "self", Type: Type_Round2, Body: &Message_Round2{Round2: &Round2Msg{D: []byte{1}}}}
	h := &round2DigestHandler{
		round1Handler: &round1Handler{
			peers: map[string]*peer{
				"p1": {
					Peer:       message.NewPeer("p1"),
					round1Data: &round1Data{round2Msg: round2Msg},
				},
			},
			peerManager: pm,
		},
	}
	next, err := h.Finalize(log.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := next.(*round2Handler); !ok {
		t.Fatal("expected round2Handler")
	}
	if len(pm.sent) != 1 || pm.sent[0] != "p1" {
		t.Fatalf("expected round2 reveal sent, got %v", pm.sent)
	}
}

func TestRound3DigestFinalizeSuccess(t *testing.T) {
	pm := &recordPM{staticPM: staticPM{self: "self"}}
	pending := map[string]*Message{
		"p1": {Id: "self", Type: Type_Round3, Body: &Message_Round3{Round3: &Round3Msg{Delta: "1"}}},
	}
	h := &round3DigestHandler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				peers:       map[string]*peer{"p1": {Peer: message.NewPeer("p1")}},
				peerManager: pm,
			},
		},
		pendingRound3: pending,
	}
	next, err := h.Finalize(log.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := next.(*round3Handler); !ok {
		t.Fatal("expected round3Handler")
	}
	if len(pm.sent) != 1 {
		t.Fatalf("expected pending Round3 sent, got %v", pm.sent)
	}
}

func TestRoundHandlersIsHandledPeerNotFound(t *testing.T) {
	logger := log.New()
	r1 := &round1Handler{peers: map[string]*peer{}, peerManager: &staticPM{self: "self"}}
	if r1.IsHandled(logger, "missing") {
		t.Fatal("round1 should not handle unknown peer")
	}
	r2 := &round2Handler{round1Handler: r1}
	if r2.IsHandled(logger, "missing") {
		t.Fatal("round2 should not handle unknown peer")
	}
	r3 := &round3Handler{round2Handler: r2}
	if r3.IsHandled(logger, "missing") {
		t.Fatal("round3 should not handle unknown peer")
	}
	r4 := &round4Handler{round3Handler: r3}
	if r4.IsHandled(logger, "missing") {
		t.Fatal("round4 should not handle unknown peer")
	}
}

func TestRound1HandleMessagePeerNotFound(t *testing.T) {
	h := &round1Handler{
		peers:       map[string]*peer{},
		peerManager: &staticPM{self: "self"},
	}
	err := h.HandleMessage(log.New(), &Message{Id: "missing", Type: Type_Round1})
	if err != tss.ErrPeerNotFound {
		t.Fatalf("want ErrPeerNotFound, got %v", err)
	}
}

func TestGetResultWrongHandlerInDoneState(t *testing.T) {
	sign := &Sign{
		MessageMain: &stubMessageMain{state: types.StateDone, handler: &round1Handler{}},
	}
	_, err := sign.GetResult()
	if err != tss.ErrNotReady {
		t.Fatalf("want ErrNotReady, got %v", err)
	}
}

func TestGetBlamedPeersFallbackErr1Handler(t *testing.T) {
	ssidInfoWithBK := []byte("fallback-eh1")
	k1 := big.NewInt(5)
	k2 := big.NewInt(2)
	K1, rho1, err := errPaillierKeyA.EncryptWithOutputSalt(k1)
	if err != nil {
		t.Fatal(err)
	}
	K2, rho2, err := errPaillierKeyB.EncryptWithOutputSalt(k2)
	if err != nil {
		t.Fatal(err)
	}
	gamma1 := big.NewInt(11)
	gamma2 := big.NewInt(10)
	G1, mu1, err := errPaillierKeyA.EncryptWithOutputSalt(gamma1)
	if err != nil {
		t.Fatal(err)
	}
	G2, mu2, err := errPaillierKeyB.EncryptWithOutputSalt(gamma2)
	if err != nil {
		t.Fatal(err)
	}
	Gamma1 := errTestG.ScalarMult(gamma1)
	Gamma2 := errTestG.ScalarMult(gamma2)
	sumGamma := errTestG.ScalarMult(gamma1)
	sumGamma, err = sumGamma.Add(Gamma2)
	if err != nil {
		t.Fatal(err)
	}
	bigDelta1 := sumGamma.ScalarMult(k1)
	bigDelta2 := sumGamma.ScalarMult(k2)
	ID1 := tss.GetTestID(0)
	ID2 := tss.GetTestID(1)

	p1Setup, p2Setup := setupErr1PartiesTesting(t, ssidInfoWithBK, errPaillierKeyA, errPaillierKeyB, k1, k2, K1, K2, G1, G2, gamma1, gamma2, Gamma1, Gamma2, bigDelta1, bigDelta2, ID1, ID2)
	p3 := newRound3HandlerErr1(k1, gamma1, rho1, mu1, K1, G1, p1Setup.delta, bigDelta1, sumGamma, errPaillierKeyA, map[string]*peer{ID2: p1Setup.peer}, 0, p1Setup.own)
	p2Err := newRound3HandlerErr1(k2, gamma2, rho2, mu2, K2, G2, p2Setup.delta, bigDelta2, sumGamma, errPaillierKeyB, map[string]*peer{ID1: p2Setup.peer}, 1, p2Setup.own)
	if err := p2Err.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	eh, err := newErr1Handler(p3, ErrInvalidDelta)
	if err != nil {
		t.Fatal(err)
	}
	collector := cggmp.NewAbortMsgCollector[*Message]()
	collector.Record(&Message{Id: ID2, Type: Type_Err1, Body: p2Err.err1Msg.Body})
	sign := &Sign{
		abortCollector: collector,
		MessageMain:    &stubMessageMain{state: types.StateFailed, handler: eh},
	}
	blamed, err := sign.GetBlamedPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed) != 0 {
		t.Fatalf("expected empty blame, got %v", blamed)
	}
}

func TestGetBlamedPeersFallbackErr2Handler(t *testing.T) {
	ssidInfoWithBK := []byte("fallback-eh2")
	k1 := big.NewInt(5)
	k2 := big.NewInt(2)
	K1, rho1, err := errPaillierKeyA.EncryptWithOutputSalt(k1)
	if err != nil {
		t.Fatal(err)
	}
	K2, rho2, err := errPaillierKeyB.EncryptWithOutputSalt(k2)
	if err != nil {
		t.Fatal(err)
	}
	b1 := big.NewInt(3)
	b2 := big.NewInt(10)
	x1 := big.NewInt(2)
	x2 := big.NewInt(3)
	bk1 := big.NewInt(2)
	bk2 := big.NewInt(-1)
	rX := big.NewInt(17)
	R := errTestG.ScalarMult(rX)
	ID1 := tss.GetTestID(0)
	ID2 := tss.GetTestID(1)
	bkMulShare1 := new(big.Int).Mul(x1, bk1)
	bkMulShare2 := new(big.Int).Mul(x2, bk2)
	bkPartial1 := errTestG.ScalarMult(x1).ScalarMult(bk1)
	bkPartial2 := errTestG.ScalarMult(x2).ScalarMult(bk2)

	p1Setup, p2Setup := setupErr2PartiesTesting(t, ssidInfoWithBK, errPaillierKeyA, errPaillierKeyB, K1, K2, k1, k2, x1, x2, bkMulShare1, bkMulShare2, bkPartial1, bkPartial2, rX, ID1, ID2)
	p4 := newRound4HandlerErr2(b1, k1, rho1, rX, K1, errPaillierKeyA, map[string]*peer{ID2: p1Setup.peer}, 0, p1Setup.own)
	p2Err := newRound4HandlerErr2(b2, k2, rho2, rX, K2, errPaillierKeyB, map[string]*peer{ID1: p2Setup.peer}, 1, p2Setup.own)
	p4.R = R
	p2Err.R = R
	p4.chi = p1Setup.chi
	p2Err.chi = p2Setup.chi
	p4.sigma = p1Setup.sigma
	p2Err.sigma = p2Setup.sigma
	p4.bkMulShare = bkMulShare1
	p2Err.bkMulShare = bkMulShare2
	p4.bkpartialPubKey = bkPartial1
	p2Err.bkpartialPubKey = bkPartial2
	if err := p2Err.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	eh, err := newErr2Handler(p4, ErrIncorrectSig)
	if err != nil {
		t.Fatal(err)
	}
	collector := cggmp.NewAbortMsgCollector[*Message]()
	collector.Record(&Message{Id: ID2, Type: Type_Err2, Body: p2Err.err2Msg.Body})
	sign := &Sign{
		abortCollector: collector,
		MessageMain:    &stubMessageMain{state: types.StateFailed, handler: eh},
	}
	blamed, err := sign.GetBlamedPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed) != 0 {
		t.Fatalf("expected empty blame, got %v", blamed)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
