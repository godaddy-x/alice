package sign

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
)

type trackingMessageMain struct {
	stubMessageMain
	started bool
}

func (m *trackingMessageMain) Start() { m.started = true }

type manyPeersPM struct{ self string }

func (m *manyPeersPM) NumPeers() uint32          { return cggmp.MaxIARemotePeers + 1 }
func (m *manyPeersPM) PeerIDs() []string         { return nil }
func (m *manyPeersPM) SelfID() string            { return m.self }
func (m *manyPeersPM) MustSend(string, interface{}) {}

func TestRound2PairwiseDigestNil(t *testing.T) {
	_, err := Round2PairwiseDigest([]byte("ssid"), "a", "b", nil)
	if err != ErrPairwiseDigestTable {
		t.Fatalf("want table err, got %v", err)
	}
}

func TestSignStartPrepareAndBroadcast(t *testing.T) {
	ssid := []byte("start-ok")
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
	r1d := &round1DigestHandler{
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
	mm := &trackingMessageMain{stubMessageMain: stubMessageMain{state: types.StateInit}}
	sign := &Sign{r1d: r1d, MessageMain: mm}
	sign.Start()
	if !mm.started {
		t.Fatal("MessageMain.Start should run after successful prepare")
	}
	if r1d.digestMsg == nil {
		t.Fatal("expected digestMsg after prepare")
	}
	if len(pm.sent) != 1 || pm.sent[0] != "p1" {
		t.Fatalf("expected digest broadcast, got %v", pm.sent)
	}
}

func TestBroadcastRound1DigestNilMessageNoOp(t *testing.T) {
	h := &round1DigestHandler{round1Handler: &round1Handler{peerManager: &recordPM{staticPM: staticPM{self: "self"}}}}
	h.broadcastRound1Digest()
}

func TestGetBlamedPeersNotReady(t *testing.T) {
	sign := &Sign{MessageMain: &stubMessageMain{state: types.StateInit}}
	_, err := sign.GetBlamedPeers()
	if err != ErrBlamedPeersNotReady {
		t.Fatalf("want ErrBlamedPeersNotReady, got %v", err)
	}
}

func TestGetBlamedPeersFallbackRound3Handler(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	collector := cggmp.NewAbortMsgCollector[*Message]()
	collector.Record(remote)
	sign := &Sign{
		abortCollector: collector,
		MessageMain:    &stubMessageMain{state: types.StateFailed, handler: p3},
	}
	blamed, err := sign.GetBlamedPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed) != 0 {
		t.Fatalf("expected empty blame for valid remote err1, got %v", blamed)
	}
}

func TestGetBlamedPeersFallbackRound4Handler(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	collector := cggmp.NewAbortMsgCollector[*Message]()
	collector.Record(remote)
	sign := &Sign{
		abortCollector: collector,
		MessageMain:    &stubMessageMain{state: types.StateFailed, handler: p4},
	}
	blamed, err := sign.GetBlamedPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed) != 0 {
		t.Fatalf("expected empty blame for valid remote err2, got %v", blamed)
	}
}

func TestSetAbortTimeoutNilMsNoPanic(t *testing.T) {
	sign := &Sign{}
	sign.SetAbortTimeout(0)
}

func TestNewRound1HandlerTooManyParticipants(t *testing.T) {
	curve := elliptic.Secp256k1()
	pub := pt.ScalarBaseMult(curve, big.NewInt(1))
	self := tss.GetTestID(0)
	bks := map[string]*birkhoffinterpolation.BkParameter{self: birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0)}
	partial := map[string]*pt.ECPoint{self: pub}
	ped := map[string]*paillierzkproof.PederssenOpenParameter{self: errPedZKA}
	_, err := newRound1Handler(
		1,
		[]byte("ssid"),
		big.NewInt(1),
		pub,
		partial,
		errPaillierKeyA,
		ped,
		bks,
		[]byte("msg"),
		&manyPeersPM{self: self},
	)
	if err == nil {
		t.Fatal("expected participant count error")
	}
}

func TestNewRound1HandlerInvalidBkThreshold(t *testing.T) {
	curve := elliptic.Secp256k1()
	pub := pt.ScalarBaseMult(curve, big.NewInt(1))
	self := tss.GetTestID(0)
	peer := tss.GetTestID(1)
	bks := map[string]*birkhoffinterpolation.BkParameter{
		self: birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0),
		peer: birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0),
	}
	partial := map[string]*pt.ECPoint{self: pub, peer: pub}
	ped := map[string]*paillierzkproof.PederssenOpenParameter{
		self: errPedZKA,
		peer: errPedZKB,
	}
	pm := tss.NewTestPeerManager(0, 2)
	_, err := newRound1Handler(
		99,
		[]byte("ssid"),
		big.NewInt(1),
		pub,
		partial,
		errPaillierKeyA,
		ped,
		bks,
		[]byte("msg"),
		pm,
	)
	if err == nil {
		t.Fatal("expected bk validation error")
	}
}

func TestProcessErr1MsgBlamesMissingRound1Data(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	p3.peers[tss.GetTestID(1)].round1Data = nil
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for missing round1 data")
	}
}

func TestProcessErr1MsgBlamesMissingRound2Data(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	p3.peers[tss.GetTestID(1)].round2Data = nil
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for missing round2 data")
	}
}

func TestProcessErr1MsgBlamesPeerKeysMismatch(t *testing.T) {
	p3, p2Err, _ := buildErr1Messages(t)
	selfID := tss.GetTestID(0)
	senderID := tss.GetTestID(1)
	src := p2Err.err1Msg.GetErr1().Peers[selfID]
	bad := &Message{Id: senderID, Type: Type_Err1, Body: &Message_Err1{Err1: &Err1Msg{
		KgammaCiphertext: p2Err.err1Msg.GetErr1().KgammaCiphertext,
		MulProof:         p2Err.err1Msg.GetErr1().MulProof,
		Peers: map[string]*Err1PeerMsg{
			selfID:  src,
			"extra": src,
		},
	}}}
	blamed, err := p3.ProcessErr1Msg([]*Message{bad})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[senderID]; !ok {
		t.Fatal("expected sender blamed for peer key mismatch")
	}
}

func TestProcessErr1MsgBlamesReconstructProductFailure(t *testing.T) {
	p3, p2Err, _ := buildErr1Messages(t)
	selfID := tss.GetTestID(0)
	senderID := tss.GetTestID(1)
	src := p2Err.err1Msg.GetErr1().Peers[selfID]
	bad := &Message{Id: senderID, Type: Type_Err1, Body: &Message_Err1{Err1: &Err1Msg{
		KgammaCiphertext: p2Err.err1Msg.GetErr1().KgammaCiphertext,
		MulProof:         p2Err.err1Msg.GetErr1().MulProof,
		Peers: map[string]*Err1PeerMsg{
			selfID: {
				D:                 src.GetD(),
				F:                 big.NewInt(0).Bytes(),
				DecModQ:           src.DecModQ,
				ProductCiphertext: src.ProductCiphertext,
			},
		},
	}}}
	blamed, err := p3.ProcessErr1Msg([]*Message{bad})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[senderID]; !ok {
		t.Fatal("expected sender blamed for reconstruct failure")
	}
}

func TestProcessErr1MsgBlamesMatchDecModQFailure(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	entry := remote.GetErr1().Peers[tss.GetTestID(0)]
	if entry == nil || entry.DecModQ == nil {
		t.Fatal("missing dec mod q proof")
	}
	entry.DecModQ.S = []byte{0xff}
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for dec mod q failure")
	}
}

func TestProcessErr1MsgBlamesNilRound3BodyInAggregate(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	round3Msg := p3.peers[tss.GetTestID(1)].GetMessage(types.MessageType(Type_Round3))
	if round3Msg == nil {
		t.Fatal("missing round3 message")
	}
	getMessage(round3Msg).Body = &Message_Round3{}
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for nil round3 body")
	}
}

func TestProcessErr1MsgBlamesBigDeltaToPointInAggregate(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	round3Msg := p3.peers[tss.GetTestID(1)].GetMessage(types.MessageType(Type_Round3))
	if round3Msg == nil {
		t.Fatal("missing round3 message")
	}
	getMessage(round3Msg).GetRound3().BigDelta = &pt.EcPointMessage{Curve: 999, X: []byte{1}, Y: []byte{2}}
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for invalid bigDelta")
	}
}

func TestProcessErr2MsgBlamesNilR(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	p4.R = nil
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed when R is nil")
	}
}

func TestProcessErr2MsgBlamesNilMsg(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	p4.msg = nil
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed when msg is nil")
	}
}

func TestProcessErr2MsgBlamesBadChi(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	q := errTestPublicKey.GetCurve().Params().N
	remote.GetErr2().Chi = make([]byte, (q.BitLen()+7)/8)
	for i := range remote.GetErr2().Chi {
		remote.GetErr2().Chi[i] = 0xff
	}
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for invalid chi")
	}
}

func TestProcessErr2MsgBlamesMissingKCiphertext(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	p4.peers[tss.GetTestID(1)].round1Data.kCiphertext = nil
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for missing k ciphertext")
	}
}

func TestProcessErr2MsgBlamesPeerKeysMismatch(t *testing.T) {
	p4, p2Err, _ := buildErr2Messages(t)
	selfID := tss.GetTestID(0)
	senderID := tss.GetTestID(1)
	src := p2Err.err2Msg.GetErr2().Peers[selfID]
	bad := &Message{Id: senderID, Type: Type_Err2, Body: &Message_Err2{Err2: &Err2Msg{
		KMulBkShareCiphertext: p2Err.err2Msg.GetErr2().KMulBkShareCiphertext,
		Chi:                   p2Err.err2Msg.GetErr2().Chi,
		Peers: map[string]*Err2PeerMsg{
			selfID:  src,
			"extra": src,
		},
	}}}
	blamed, err := p4.ProcessErr2Msg([]*Message{bad})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[senderID]; !ok {
		t.Fatal("expected sender blamed for peer key mismatch")
	}
}

func TestProcessErr2MsgBlamesMatchDecModQFailure(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	entry := remote.GetErr2().Peers[tss.GetTestID(0)]
	if entry == nil || entry.DecModQ == nil {
		t.Fatal("missing dec mod q proof")
	}
	entry.DecModQ.S = []byte{0xff}
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for dec mod q failure")
	}
}

func TestDecModQWitnessLiftFails(t *testing.T) {
	curveN := errTestPublicKey.GetCurve().Params().N
	c, _, err := errPaillierKeyA.EncryptWithOutputSalt(big.NewInt(3))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = decModQWitness(errPaillierKeyA, c, big.NewInt(999999), curveN)
	if err == nil {
		t.Fatal("expected lift failure with mismatched proofX")
	}
}
