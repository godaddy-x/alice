package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

func TestErr1HandlerAPI(t *testing.T) {
	p3 := &round3Handler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				peerNum:     1,
				peerManager: &staticPM{self: "self"},
			},
		},
	}
	eh, err := newErr1Handler(p3, ErrInvalidDelta)
	if err != nil {
		t.Fatal(err)
	}
	if eh.MessageType() != types.MessageType(Type_Err1) {
		t.Fatal("wrong message type")
	}
	if eh.GetRequiredMessageCount() != 2 {
		t.Fatal("wrong required count")
	}
	if eh.InitialMsgCount() != 0 {
		t.Fatal("expected zero initial msgs")
	}
	if !eh.AbortCollecting() {
		t.Fatal("expected abort collecting")
	}
	if eh.IsHandled(log.New(), "missing") {
		t.Fatal("unexpected handled")
	}
	if err := eh.HandleMessage(log.New(), &Message{Id: "p1", Type: Type_Err1, Body: &Message_Err1{Err1: &Err1Msg{}}}); err != nil {
		t.Fatal(err)
	}
	if !eh.IsHandled(log.New(), "p1") {
		t.Fatal("expected handled after message")
	}
}

func TestErr2HandlerAPI(t *testing.T) {
	p4 := &round4Handler{
		round3Handler: &round3Handler{
			round2Handler: &round2Handler{
				round1Handler: &round1Handler{
					peerNum:     1,
					peerManager: &staticPM{self: "self"},
				},
			},
		},
	}
	eh, err := newErr2Handler(p4, ErrIncorrectSig)
	if err != nil {
		t.Fatal(err)
	}
	if eh.MessageType() != types.MessageType(Type_Err2) {
		t.Fatal("wrong message type")
	}
	if eh.GetRequiredMessageCount() != 2 {
		t.Fatal("wrong required count")
	}
	if eh.InitialMsgCount() != 0 {
		t.Fatal("expected zero initial msgs")
	}
	if !eh.AbortCollecting() {
		t.Fatal("expected abort collecting")
	}
	if eh.IsHandled(log.New(), "missing") {
		t.Fatal("unexpected handled")
	}
	if err := eh.HandleMessage(log.New(), &Message{Id: "p1", Type: Type_Err2, Body: &Message_Err2{Err2: &Err2Msg{}}}); err != nil {
		t.Fatal(err)
	}
	if !eh.IsHandled(log.New(), "p1") {
		t.Fatal("expected handled after message")
	}
}

func TestRound2DigestHandleMessageSuccess(t *testing.T) {
	ssid := []byte("ssid-r2-digest-ok")
	self := "id-0"
	sender := "id-1"
	r2 := &Round2Msg{D: []byte{1}, F: []byte{2}, Dhat: []byte{3}, Fhat: []byte{4}}
	want, err := Round2PairwiseDigest(ssid, sender, self, r2)
	if err != nil {
		t.Fatal(err)
	}
	entries, root := commitDigestTable(ssid, tagR2, sender, map[string][]byte{self: want})
	gamma := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(5))
	gammaMsg, err := gamma.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}

	h := &round2DigestHandler{
		round1Handler: &round1Handler{
			ssid:        ssid,
			digestStore: newPairwiseDigestStore(),
			peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager: &staticPM{self: self},
		},
	}
	err = h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round2Digest,
		Body: &Message_Round2Digest{
			Round2Digest: &Round2DigestMsg{
				Gamma:     gammaMsg,
				ToPeer:    entries,
				TableRoot: root,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.peers[sender].digestGamma == nil || !h.peers[sender].digestGamma.Equal(gamma) {
		t.Fatal("gamma not stashed")
	}
}

func TestRound3DigestHandleMessageSuccess(t *testing.T) {
	ssid := []byte("ssid-r3-digest-ok")
	self := "id-0"
	sender := "id-1"
	psi := &paillierzkproof.LogStarMessage{}
	want, err := Round3PairwiseDigest(ssid, sender, self, psi)
	if err != nil {
		t.Fatal(err)
	}
	entries, root := commitDigestTable(ssid, tagR3, sender, map[string][]byte{self: want})
	bigDelta := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(3))
	bigDeltaMsg, err := bigDelta.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}

	h := &round3DigestHandler{
		round2Handler: &round2Handler{
			round1Handler: &round1Handler{
				ssid:        ssid,
				digestStore: newPairwiseDigestStore(),
				peers:       map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
				peerManager: &staticPM{self: self},
			},
		},
	}
	err = h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round3Digest,
		Body: &Message_Round3Digest{
			Round3Digest: &Round3DigestMsg{
				Delta:     "42",
				BigDelta:  bigDeltaMsg,
				ToPeer:    entries,
				TableRoot: root,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := h.peers[sender]
	if peer.digestDelta != "42" || peer.digestBigDelta == nil || !peer.digestBigDelta.Equal(bigDelta) {
		t.Fatal("delta/bigDelta not stashed")
	}
}

func TestRound2DigestHandleMessageInvalidTableBlames(t *testing.T) {
	ssid := []byte("ssid-r2-table")
	self := "id-0"
	sender := "id-1"
	sign := &Sign{}
	gammaMsg, err := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(1)).ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	h := &round2DigestHandler{
		round1Handler: &round1Handler{
			ssid:          ssid,
			digestStore:   newPairwiseDigestStore(),
			peers:         map[string]*peer{sender: {Peer: message.NewPeer(sender)}},
			peerManager:   &staticPM{self: self},
			onBlame: sign.storeBlame,
		},
	}
	err = h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round2Digest,
		Body: &Message_Round2Digest{
			Round2Digest: &Round2DigestMsg{
				Gamma:     gammaMsg,
				ToPeer:    []*PeerDigestEntry{},
				TableRoot: make([]byte, 32),
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
