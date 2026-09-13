package sign

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

func buildErr1Messages(t *testing.T) (*round3Handler, *round3Handler, *Message) {
	t.Helper()
	p3, p2Err := setupRound3PairForErr1Testing(t)
	if err := p2Err.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	if err := p3.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err1, Body: p2Err.err1Msg.Body}
	return p3, p2Err, remote
}

func buildErr2Messages(t *testing.T) (*round4Handler, *round4Handler, *Message) {
	t.Helper()
	p4, p2Err := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	if err := p2Err.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	remote := &Message{Id: tss.GetTestID(1), Type: Type_Err2, Body: p2Err.err2Msg.Body}
	return p4, p2Err, remote
}

func TestProcessErr1MsgAcceptsValidRemote(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed.Union()) != 0 {
		t.Fatalf("expected no blame, got %v", blamed)
	}
}

func TestProcessErr1MsgBlamesAbsentSender(t *testing.T) {
	p3, _, _ := buildErr1Messages(t)
	blamed, err := p3.ProcessErr1Msg(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected absent peer blamed")
	}
}

func TestProcessErr1MsgSkipsSelfAndUnknown(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	selfMsg := &Message{Id: tss.GetTestID(0), Type: Type_Err1, Body: p3.err1Msg.Body}
	unknown := &Message{Id: "unknown", Type: Type_Err1, Body: remote.Body}
	blamed, err := p3.ProcessErr1Msg([]*Message{selfMsg, unknown, remote})
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed.Union()) != 0 {
		t.Fatalf("expected no blame, got %v", blamed)
	}
}

func TestProcessErr1MsgBlamesIncompletePeerState(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	p3.peers[tss.GetTestID(1)].round3Data = nil
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected peer blamed for missing round3 data")
	}
}

func TestProcessErr1MsgBlamesNilBody(t *testing.T) {
	p3, _, _ := buildErr1Messages(t)
	bad := &Message{Id: tss.GetTestID(1), Type: Type_Err1}
	blamed, err := p3.ProcessErr1Msg([]*Message{bad})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected peer blamed for nil err1 body")
	}
}

func TestProcessErr1MsgBlamesMissingProofFields(t *testing.T) {
	p3, p2Err, _ := buildErr1Messages(t)
	bad := &Message{Id: tss.GetTestID(1), Type: Type_Err1, Body: &Message_Err1{Err1: &Err1Msg{
		KgammaCiphertext: p2Err.err1Msg.GetErr1().KgammaCiphertext,
		Peers:            map[string]*Err1PeerMsg{},
	}}}
	blamed, err := p3.ProcessErr1Msg([]*Message{bad})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected peer blamed for missing mul proof")
	}
}

func TestProcessErr1MsgBlamesTamperedDF(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	peerMsg := remote.GetErr1().Peers[tss.GetTestID(0)]
	if peerMsg == nil {
		t.Fatal("missing peer entry")
	}
	peerMsg.D[0] ^= 0xff
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for tampered D/F")
	}
}

func TestProcessErr1MsgBlamesDeltaCrossCheckFailure(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	round3Msg := p3.peers[tss.GetTestID(1)].GetMessage(types.MessageType(Type_Round3))
	if round3Msg == nil {
		t.Fatal("missing round3 message")
	}
	wrong, err := errTestG.ScalarMult(big.NewInt(999)).ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	getMessage(round3Msg).GetRound3().BigDelta = wrong
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for delta cross-check failure")
	}
}

func TestProcessErr1MsgTooManyParticipants(t *testing.T) {
	peers := make(map[string]*peer, 9)
	for i := 0; i < 9; i++ {
		id := tss.GetTestID(i + 1)
		peers[id] = &peer{Peer: message.NewPeer(id)}
	}
	p3 := &round3Handler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				peers:       peers,
				peerNum:     9,
				peerManager: &staticPM{self: tss.GetTestID(0)},
				pubKey:      errTestPublicKey,
			},
		},
	}
	_, err := p3.ProcessErr1Msg(nil)
	if err == nil {
		t.Fatal("expected participant count error")
	}
}

func TestProcessErr2MsgAcceptsValidRemote(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed.Union()) != 0 {
		t.Fatalf("expected no blame, got %v", blamed)
	}
}

func TestProcessErr2MsgBlamesAbsentSender(t *testing.T) {
	p4, _, _ := buildErr2Messages(t)
	blamed, err := p4.ProcessErr2Msg(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected absent peer blamed")
	}
}

func TestProcessErr2MsgBlamesMissingRound4Data(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	p4.peers[tss.GetTestID(1)].round4Data = nil
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected peer blamed for missing round4 data")
	}
}

func TestProcessErr2MsgBlamesMissingMulStar(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	for _, entry := range remote.GetErr2().Peers {
		entry.MulStarProof = nil
	}
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for missing mul star proof")
	}
}

func TestProcessErr2MsgBlamesTamperedProduct(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	entry := remote.GetErr2().Peers[tss.GetTestID(0)]
	if entry == nil || len(entry.ProductCiphertext) == 0 {
		t.Fatal("missing product ciphertext")
	}
	entry.ProductCiphertext[0] ^= 0xff
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for product mismatch")
	}
}

func TestProcessErr2MsgBlamesBadDecModQKm(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	entry := remote.GetErr2().Peers[tss.GetTestID(0)]
	if entry == nil || entry.DecModQKm == nil {
		t.Fatal("missing dec mod q km proof")
	}
	entry.DecModQKm.S = []byte{0xff}
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for bad DecModQKm")
	}
}

func TestProcessErr2MsgTooManyParticipants(t *testing.T) {
	peers := make(map[string]*peer, 9)
	for i := 0; i < 9; i++ {
		id := tss.GetTestID(i + 1)
		peers[id] = &peer{Peer: message.NewPeer(id)}
	}
	p4 := &round4Handler{
		round3Handler: &round3Handler{
			round2Handler: &round2Handler{
				round1Handler: &round1Handler{
					peers:       peers,
					peerNum:     9,
					peerManager: &staticPM{self: tss.GetTestID(0)},
					pubKey:      errTestPublicKey,
				},
			},
		},
	}
	_, err := p4.ProcessErr2Msg(nil)
	if err == nil {
		t.Fatal("expected participant count error")
	}
}

func TestErr1HandlerFinalizeReturnsProcessError(t *testing.T) {
	peers := make(map[string]*peer, 9)
	for i := 0; i < 9; i++ {
		id := tss.GetTestID(i + 1)
		peers[id] = &peer{Peer: message.NewPeer(id)}
	}
	p3 := &round3Handler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				peers:       peers,
				peerNum:     9,
				peerManager: &staticPM{self: tss.GetTestID(0)},
				pubKey:      errTestPublicKey,
			},
		},
	}
	eh, err := newErr1Handler(p3, ErrInvalidDelta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eh.Finalize(log.New()); err == nil {
		t.Fatal("expected finalize process error")
	}
}

func TestErr2HandlerFinalizeReturnsProcessError(t *testing.T) {
	peers := make(map[string]*peer, 9)
	for i := 0; i < 9; i++ {
		id := tss.GetTestID(i + 1)
		peers[id] = &peer{Peer: message.NewPeer(id)}
	}
	p4 := &round4Handler{
		round3Handler: &round3Handler{
			round2Handler: &round2Handler{
				round1Handler: &round1Handler{
					peers:       peers,
					peerNum:     9,
					peerManager: &staticPM{self: tss.GetTestID(0)},
					pubKey:      errTestPublicKey,
				},
			},
		},
	}
	eh, err := newErr2Handler(p4, ErrIncorrectSig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eh.Finalize(log.New()); err == nil {
		t.Fatal("expected finalize process error")
	}
}

func TestProcessErr1MsgBlamesSessionRound2Mismatch(t *testing.T) {
	p3, p2Err, remote := buildErr1Messages(t)
	ssid := []byte("digest-bind-err1")
	p3.ssid = ssid
	peer := p3.peers[tss.GetTestID(1)]
	r2Body := &Round2Msg{
		D:   peer.round2Data.d.Bytes(),
		F:   peer.round2Data.f.Bytes(),
		Psi: peer.round2Data.psiProof,
	}
	if err := peer.AddMessage(&Message{
		Id: tss.GetTestID(1), Type: Type_Round2, Body: &Message_Round2{Round2: r2Body},
	}); err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	wrong, err := Round2PairwiseDigest(ssid, tss.GetTestID(1), tss.GetTestID(0), &Round2Msg{D: []byte{0xff}})
	if err != nil {
		t.Fatal(err)
	}
	store.SetFinalized(digestR2, tss.GetTestID(1), map[string][]byte{tss.GetTestID(0): wrong})
	p3.digestStore = store
	_ = p2Err
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for session round2 mismatch")
	}
}

func TestProcessErr1MsgBlamesMulProofVerifyFail(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	if len(remote.GetErr1().KgammaCiphertext) == 0 {
		t.Fatal("missing kgamma ciphertext")
	}
	remote.GetErr1().KgammaCiphertext[0] ^= 0xff
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for bad mul proof")
	}
}

func TestProcessErr1MsgBlamesMissingRound3Message(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	delete(p3.peers[tss.GetTestID(1)].Messages, types.MessageType(Type_Round3))
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for missing round3 message")
	}
}

func TestProcessErr1MsgBlamesEmptyProductComponents(t *testing.T) {
	p3, p2Err, _ := buildErr1Messages(t)
	selfID := tss.GetTestID(0)
	senderID := tss.GetTestID(1)
	src := p2Err.err1Msg.GetErr1().Peers[selfID]
	bad := &Message{Id: senderID, Type: Type_Err1, Body: &Message_Err1{Err1: &Err1Msg{
		KgammaCiphertext: p2Err.err1Msg.GetErr1().KgammaCiphertext,
		MulProof:         p2Err.err1Msg.GetErr1().MulProof,
		Peers: map[string]*Err1PeerMsg{
			selfID: {D: []byte{}, F: src.GetF(), DecModQ: src.DecModQ, ProductCiphertext: src.ProductCiphertext},
		},
	}}}
	blamed, err := p3.ProcessErr1Msg([]*Message{bad})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[senderID]; !ok {
		t.Fatal("expected sender blamed for empty product components")
	}
}

func TestProcessErr2MsgBlamesSessionRound2Mismatch(t *testing.T) {
	p4, p2Err, remote := buildErr2Messages(t)
	ssid := []byte("digest-bind-err2")
	p4.ssid = ssid
	peer := p4.peers[tss.GetTestID(1)]
	r2Body := &Round2Msg{
		Dhat:   peer.round2Data.dhat.Bytes(),
		Fhat:   peer.round2Data.fhat.Bytes(),
		Psihat: peer.round2Data.psihatProoof,
	}
	if err := peer.AddMessage(&Message{
		Id: tss.GetTestID(1), Type: Type_Round2, Body: &Message_Round2{Round2: r2Body},
	}); err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	wrong, err := Round2PairwiseDigest(ssid, tss.GetTestID(1), tss.GetTestID(0), &Round2Msg{Dhat: []byte{0xff}})
	if err != nil {
		t.Fatal(err)
	}
	store.SetFinalized(digestR2, tss.GetTestID(1), map[string][]byte{tss.GetTestID(0): wrong})
	p4.digestStore = store
	_ = p2Err
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed.Union()[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for session round2 mismatch")
	}
}

func TestErr1HandlerFinalizeWithoutCallback(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	remote.GetErr1().Peers = map[string]*Err1PeerMsg{}
	eh, err := newErr1Handler(p3, ErrInvalidDelta)
	if err != nil {
		t.Fatal(err)
	}
	if err := eh.HandleMessage(log.New(), remote); err != nil {
		t.Fatal(err)
	}
	p3.onBlame = nil
	_, finalizeErr := eh.Finalize(log.New())
	if finalizeErr != ErrInvalidDelta {
		t.Fatalf("want ErrInvalidDelta, got %v", finalizeErr)
	}
}
