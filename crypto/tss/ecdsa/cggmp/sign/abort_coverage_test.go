package sign

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/tss"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

func TestBlamePeerNoCallback(t *testing.T) {
	p3 := &round3Handler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{onBlamedPeers: nil},
		},
	}
	p3.blamePeer("peer")
}

func TestBlamePeerInvokesCallback(t *testing.T) {
	var blamed string
	p3 := &round3Handler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				onBlamedPeers: func(m map[string]struct{}) {
					for id := range m {
						blamed = id
					}
				},
			},
		},
	}
	p3.blamePeer("evil")
	if blamed != "evil" {
		t.Fatalf("want evil blamed, got %q", blamed)
	}
}

func TestEnsureErr1BuiltSkipsWhenMessageReady(t *testing.T) {
	p3 := setupRound3ForErr1Testing(t)
	if err := p3.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	if err := p3.ensureErr1Built(); err != nil {
		t.Fatal(err)
	}
	if p3.err1Msg == nil {
		t.Fatal("expected err1 message")
	}
}

func TestPublishErr1NilMessageNoOp(t *testing.T) {
	p3 := &round3Handler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{peerManager: &staticPM{self: "self"}},
		},
	}
	p3.publishErr1()
}

func TestPublishErr1RecordsAndBroadcasts(t *testing.T) {
	p3, p2Err := setupRound3PairForErr1Testing(t)
	if err := p3.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	var recorded *Message
	p3.onAbortMsg = func(m *Message) { recorded = m }
	pm := &recordPM{staticPM: staticPM{self: tss.GetTestID(0)}}
	p3.peerManager = pm
	p3.publishErr1()
	if recorded == nil {
		t.Fatal("expected onAbortMsg callback")
	}
	if len(pm.sent) == 0 {
		t.Fatal("expected broadcast")
	}
	_ = p2Err
}

func TestEnterErr1PhaseReturnsHandler(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	h, err := p3.enterErr1Phase(log.New(), ErrInvalidDelta)
	if err != nil {
		t.Fatal(err)
	}
	eh, ok := h.(*err1Handler)
	if !ok {
		t.Fatal("expected err1Handler")
	}
	if eh.abortReason != ErrInvalidDelta {
		t.Fatal("wrong abort reason")
	}
	if p3.err1Msg == nil {
		t.Fatal("expected built err1 message")
	}
}

func TestOnAbortErr1HandlesRemoteMessage(t *testing.T) {
	p3, p2Err := setupRound3PairForErr1Testing(t)
	if err := p2Err.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err1, Body: p2Err.err1Msg.Body}
	h, err := p3.onAbortErr1(log.New(), remote)
	if err != nil {
		t.Fatal(err)
	}
	eh, ok := h.(*err1Handler)
	if !ok {
		t.Fatal("expected err1Handler")
	}
	if !eh.IsHandled(log.New(), tss.GetTestID(1)) {
		t.Fatal("remote err1 should be recorded")
	}
}

func TestRound3OnAbortMessageRoutesErr1(t *testing.T) {
	p3, p2Err := setupRound3PairForErr1Testing(t)
	if err := p2Err.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err1, Body: p2Err.err1Msg.Body}
	h, err := p3.OnAbortMessage(log.New(), remote)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.(*err1Handler); !ok {
		t.Fatal("expected err1Handler from OnAbortMessage")
	}
}

func TestEnterErr1PhaseBuildFails(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	p3.peers[tss.GetTestID(1)].round2Data.psiProof = &paillierzkproof.PaillierAffAndGroupRangeMessage{S: []byte{0xff}}
	_, err := p3.enterErr1Phase(log.New(), ErrInvalidDelta)
	if err == nil {
		t.Fatal("expected build failure")
	}
}

func TestOnAbortErr1BuildFails(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	p3.peers[tss.GetTestID(1)].round2Data.psiProof = &paillierzkproof.PaillierAffAndGroupRangeMessage{S: []byte{0xff}}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err1}
	_, err := p3.onAbortErr1(log.New(), remote)
	if err == nil {
		t.Fatal("expected build failure")
	}
}

func TestPublishErr2NilMessageNoOp(t *testing.T) {
	p4 := &round4Handler{
		round3Handler: &round3Handler{
			round2Handler: &round2Handler{
				round1Handler: &round1Handler{peerManager: &staticPM{self: "self"}},
			},
		},
	}
	p4.publishErr2()
}

func TestEnterErr2PhaseBuildFails(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	p4.peers[tss.GetTestID(1)].round2Data.psihatProoof = &paillierzkproof.PaillierAffAndGroupRangeMessage{S: []byte{0xff}}
	_, err := p4.enterErr2Phase(log.New(), ErrIncorrectSig)
	if err == nil {
		t.Fatal("expected build failure")
	}
}

func TestOnAbortErr2BuildFails(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	p4.peers[tss.GetTestID(1)].round2Data.psihatProoof = &paillierzkproof.PaillierAffAndGroupRangeMessage{S: []byte{0xff}}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err2}
	_, err := p4.onAbortErr2(log.New(), remote)
	if err == nil {
		t.Fatal("expected build failure")
	}
}

func TestRound4OnAbortMessageRoutesErr2(t *testing.T) {
	p4, p2Err := setupRound4PairForErr2Testing(t)
	if err := p2Err.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err2, Body: p2Err.err2Msg.Body}
	h, err := p4.OnAbortMessage(log.New(), remote)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.(*err2Handler); !ok {
		t.Fatal("expected err2Handler from OnAbortMessage")
	}
}

func TestRound3FinalizeEntersErr1PhaseOnBadDelta(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	curveN := errTestPublicKey.GetCurve().Params().N
	peer := p3.peers[tss.GetTestID(1)]
	peer.round3Data.delta = new(big.Int).Add(peer.round3Data.delta, big.NewInt(1))
	peer.round3Data.delta.Mod(peer.round3Data.delta, curveN)
	h, err := p3.Finalize(log.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.(*err1Handler); !ok {
		t.Fatal("expected err1Handler on delta mismatch")
	}
}

func TestEnsureErr2BuiltSkipsWhenMessageReady(t *testing.T) {
	p4 := setupRound4ForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	if err := p4.ensureErr2Built(); err != nil {
		t.Fatal(err)
	}
	if p4.err2Msg == nil {
		t.Fatal("expected err2 message")
	}
}

func TestPublishErr2RecordsAndBroadcasts(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	var recorded *Message
	p4.onAbortMsg = func(m *Message) { recorded = m }
	pm := &recordPM{staticPM: staticPM{self: tss.GetTestID(0)}}
	p4.peerManager = pm
	p4.publishErr2()
	if recorded == nil {
		t.Fatal("expected onAbortMsg callback")
	}
	if len(pm.sent) == 0 {
		t.Fatal("expected broadcast")
	}
}

func TestEnterErr2PhaseReturnsHandler(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	h, err := p4.enterErr2Phase(log.New(), ErrIncorrectSig)
	if err != nil {
		t.Fatal(err)
	}
	eh, ok := h.(*err2Handler)
	if !ok {
		t.Fatal("expected err2Handler")
	}
	if eh.abortReason != ErrIncorrectSig {
		t.Fatal("wrong abort reason")
	}
}

func TestOnAbortErr2HandlesRemoteMessage(t *testing.T) {
	p4, p2Err := setupRound4PairForErr2Testing(t)
	if err := p2Err.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err2, Body: p2Err.err2Msg.Body}
	h, err := p4.onAbortErr2(log.New(), remote)
	if err != nil {
		t.Fatal(err)
	}
	eh, ok := h.(*err2Handler)
	if !ok {
		t.Fatal("expected err2Handler")
	}
	if !eh.IsHandled(log.New(), tss.GetTestID(1)) {
		t.Fatal("remote err2 should be recorded")
	}
}

func TestRound4OnAbortMessageRoutesErr1(t *testing.T) {
	p3, p2Err := setupRound3PairForErr1Testing(t)
	if err := p2Err.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	p4 := &round4Handler{round3Handler: p3}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err1, Body: p2Err.err1Msg.Body}
	h, err := p4.OnAbortMessage(log.New(), remote)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.(*err1Handler); !ok {
		t.Fatal("expected err1Handler from Err1 route")
	}
}

func TestRound4OnAbortMessageRejectsUnknownType(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	_, err := p4.OnAbortMessage(log.New(), &Message{Id: "x", Type: Type_Round4})
	if err != ErrRemoteAbort {
		t.Fatalf("want ErrRemoteAbort, got %v", err)
	}
}

func TestRound4FinalizeEntersErr2PhaseOnBadSig(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	// Force an incorrect aggregate signature while keeping handler state otherwise valid.
	p4.peers[tss.GetTestID(1)].round4Data.sigma = big.NewInt(999999)
	h, err := p4.Finalize(log.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.(*err2Handler); !ok {
		t.Fatal("expected err2Handler on bad signature")
	}
}

func TestErr1HandlerFinalizeBlamesBadPeer(t *testing.T) {
	p3, p2Err := setupRound3PairForErr1Testing(t)
	if err := p3.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	if err := p2Err.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	var stored map[string]struct{}
	p3.onBlamedPeers = func(m map[string]struct{}) { stored = m }
	eh, err := newErr1Handler(p3, ErrInvalidDelta)
	if err != nil {
		t.Fatal(err)
	}
	bad := &Message{Id: tss.GetTestID(1), Type: Type_Err1, Body: &Message_Err1{Err1: &Err1Msg{
		KgammaCiphertext: p2Err.err1Msg.GetErr1().KgammaCiphertext,
		MulProof:         p2Err.err1Msg.GetErr1().MulProof,
		Peers:            map[string]*Err1PeerMsg{},
	}}}
	if err := eh.HandleMessage(log.New(), bad); err != nil {
		t.Fatal(err)
	}
	_, finalizeErr := eh.Finalize(log.New())
	if finalizeErr != ErrInvalidDelta {
		t.Fatalf("want ErrInvalidDelta, got %v", finalizeErr)
	}
	if _, ok := stored[tss.GetTestID(1)]; !ok {
		t.Fatal("expected remote peer blamed")
	}
}

func TestErr2HandlerFinalizeBlamesBadPeer(t *testing.T) {
	p4, p2Err := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	if err := p2Err.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	var stored map[string]struct{}
	p4.onBlamedPeers = func(m map[string]struct{}) { stored = m }
	eh, err := newErr2Handler(p4, ErrIncorrectSig)
	if err != nil {
		t.Fatal(err)
	}
	bad := &Message{Id: tss.GetTestID(1), Type: Type_Err2, Body: p2Err.err2Msg.Body}
	for _, peerMsg := range bad.GetErr2().Peers {
		peerMsg.MulStarProof = nil
	}
	if err := eh.HandleMessage(log.New(), bad); err != nil {
		t.Fatal(err)
	}
	_, finalizeErr := eh.Finalize(log.New())
	if finalizeErr != ErrIncorrectSig {
		t.Fatalf("want ErrIncorrectSig, got %v", finalizeErr)
	}
	if _, ok := stored[tss.GetTestID(1)]; !ok {
		t.Fatal("expected remote peer blamed")
	}
}

func TestNewErr1HandlerSeedsSelfMessage(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	if err := p3.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	eh, err := newErr1Handler(p3, ErrInvalidDelta)
	if err != nil {
		t.Fatal(err)
	}
	if eh.InitialMsgCount() != 1 {
		t.Fatalf("want 1 initial msg, got %d", eh.InitialMsgCount())
	}
	if !eh.IsHandled(log.New(), tss.GetTestID(0)) {
		t.Fatal("self err1 should be pre-recorded")
	}
}

func TestNewErr2HandlerSeedsSelfMessage(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	eh, err := newErr2Handler(p4, ErrIncorrectSig)
	if err != nil {
		t.Fatal(err)
	}
	if eh.InitialMsgCount() != 1 {
		t.Fatalf("want 1 initial msg, got %d", eh.InitialMsgCount())
	}
	if !eh.IsHandled(log.New(), tss.GetTestID(0)) {
		t.Fatal("self err2 should be pre-recorded")
	}
}

func TestPeerBetaCountsDefaults(t *testing.T) {
	peers := map[string]*peer{
		"p1": {Peer: message.NewPeer("p1"), round1Data: &round1Data{countDelta: big.NewInt(3), countSigma: big.NewInt(4)}},
		"p2": {Peer: message.NewPeer("p2")},
	}
	deltaCounts := peerBetaCounts(peers, false)
	if deltaCounts["p1"].Int64() != 3 {
		t.Fatal("expected countDelta")
	}
	if deltaCounts["p2"].Int64() != 0 {
		t.Fatal("expected zero default")
	}
	sigmaCounts := peerBetaCounts(peers, true)
	if sigmaCounts["p1"].Int64() != 4 {
		t.Fatal("expected countSigma")
	}
}

func TestBuildDeltaVerifyFailureMsgBlamesInvalidPsi(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	peer := p3.peers[tss.GetTestID(1)]
	peer.round2Data.psiProof = &paillierzkproof.PaillierAffAndGroupRangeMessage{S: []byte{0xff}}
	var blamed string
	p3.onBlamedPeers = func(m map[string]struct{}) {
		for id := range m {
			blamed = id
		}
	}
	if err := p3.buildDeltaVerifyFailureMsg(); err == nil {
		t.Fatal("expected verify error")
	}
	if blamed != tss.GetTestID(1) {
		t.Fatalf("want peer blamed, got %q", blamed)
	}
}

func setupRound3ForErr1Testing(t *testing.T) *round3Handler {
	t.Helper()
	p3, _ := setupRound3PairForErr1Testing(t)
	return p3
}

func setupRound3PairForErr1Testing(t *testing.T) (*round3Handler, *round3Handler) {
	t.Helper()
	ssid := []byte("abort-err1")
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
	p1Setup, p2Setup := setupErr1PartiesTesting(t, ssid, errPaillierKeyA, errPaillierKeyB, k1, k2, K1, K2, G1, G2, gamma1, gamma2, Gamma1, Gamma2, bigDelta1, bigDelta2, ID1, ID2)
	p3 := newRound3HandlerErr1(k1, gamma1, rho1, mu1, K1, G1, p1Setup.delta, bigDelta1, sumGamma, errPaillierKeyA, map[string]*peer{ID2: p1Setup.peer}, 0, p1Setup.own)
	p2 := newRound3HandlerErr1(k2, gamma2, rho2, mu2, K2, G2, p2Setup.delta, bigDelta2, sumGamma, errPaillierKeyB, map[string]*peer{ID1: p2Setup.peer}, 1, p2Setup.own)
	return p3, p2
}

func setupRound4ForErr2Testing(t *testing.T) *round4Handler {
	t.Helper()
	p4, _ := setupRound4PairForErr2Testing(t)
	return p4
}

func setupRound4PairForErr2Testing(t *testing.T) (*round4Handler, *round4Handler) {
	t.Helper()
	ssid := []byte("abort-err2")
	k1 := big.NewInt(5)
	k2 := big.NewInt(2)
	b1 := big.NewInt(3)
	b2 := big.NewInt(10)
	K1, rho1, err := errPaillierKeyA.EncryptWithOutputSalt(k1)
	if err != nil {
		t.Fatal(err)
	}
	K2, rho2, err := errPaillierKeyB.EncryptWithOutputSalt(k2)
	if err != nil {
		t.Fatal(err)
	}
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
	p1Setup, p2Setup := setupErr2PartiesTesting(t, ssid, errPaillierKeyA, errPaillierKeyB, K1, K2, k1, k2, x1, x2, bkMulShare1, bkMulShare2, bkPartial1, bkPartial2, rX, ID1, ID2)
	p4 := newRound4HandlerErr2(b1, k1, rho1, rX, K1, errPaillierKeyA, map[string]*peer{ID2: p1Setup.peer}, 0, p1Setup.own)
	p2 := newRound4HandlerErr2(b2, k2, rho2, rX, K2, errPaillierKeyB, map[string]*peer{ID1: p2Setup.peer}, 1, p2Setup.own)
	p4.R = R
	p2.R = R
	p4.chi = p1Setup.chi
	p2.chi = p2Setup.chi
	p4.sigma = p1Setup.sigma
	p2.sigma = p2Setup.sigma
	p4.bkMulShare = bkMulShare1
	p2.bkMulShare = bkMulShare2
	p4.bkpartialPubKey = bkPartial1
	p2.bkpartialPubKey = bkPartial2
	return p4, p2
}

func TestRound3HandlerAbortMessageTypes(t *testing.T) {
	p3 := &round3Handler{
		round2Handler: &round2Handler{round1Handler: &round1Handler{}},
	}
	abortTypes := p3.AbortMessageTypes()
	if len(abortTypes) != 1 || abortTypes[0] != types.MessageType(Type_Err1) {
		t.Fatal("unexpected abort types")
	}
}

func TestRound4HandlerAbortMessageTypes(t *testing.T) {
	p4 := &round4Handler{
		round3Handler: &round3Handler{
			round2Handler: &round2Handler{round1Handler: &round1Handler{}},
		},
	}
	abortTypes := p4.AbortMessageTypes()
	if len(abortTypes) != 2 {
		t.Fatalf("want 2 abort types, got %d", len(abortTypes))
	}
}

func TestRound4HandleMessagePeerNotFound(t *testing.T) {
	p4 := &round4Handler{
		round3Handler: &round3Handler{
			round2Handler: &round2Handler{
				round1Handler: &round1Handler{
					peers:       map[string]*peer{},
					peerManager: &staticPM{self: "self"},
				},
			},
		},
	}
	err := p4.HandleMessage(log.New(), &Message{Id: "missing", Type: Type_Round4})
	if err != tss.ErrPeerNotFound {
		t.Fatalf("want ErrPeerNotFound, got %v", err)
	}
}

func setRound4ValidSignature(t *testing.T, p4 *round4Handler, rX *big.Int) {
	t.Helper()
	curveN := errTestPublicKey.GetCurve().Params().N
	R := errTestG.ScalarMult(rX)
	p4.R = R
	r := R.GetX()
	m := new(big.Int).SetBytes(p4.msg)
	m.Mod(m, curveN)
	kInv := new(big.Int).ModInverse(new(big.Int).Mod(rX, curveN), curveN)
	if kInv == nil {
		t.Fatal("no modular inverse")
	}
	s := new(big.Int).Mul(kInv, new(big.Int).Add(m, r))
	s.Mod(s, curveN)
	for _, peer := range p4.peers {
		if peer.round4Data == nil {
			peer.round4Data = &round4Data{}
		}
		peer.round4Data.sigma = big.NewInt(0)
	}
	p4.sigma = s
}

func TestRound4FinalizeSuccess(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	setRound4ValidSignature(t, p4, big.NewInt(17))
	res, err := p4.Finalize(log.New())
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Fatal("expected nil handler on success")
	}
	if p4.result == nil || p4.result.R == nil || p4.result.S == nil {
		t.Fatal("expected signature result")
	}
}
