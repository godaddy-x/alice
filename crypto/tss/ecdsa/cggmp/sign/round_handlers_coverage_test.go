package sign

import (
	"errors"
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

type noopStateListener struct{}

func (noopStateListener) OnStateChanged(types.MainState, types.MainState) {}

func TestRound3DigestDeltaStringMismatchBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r3-delta-mismatch")
	self := "id-0"
	sender := "id-1"
	psi := &paillier.LogStarMessage{}
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
				onBlamedPeers: sign.storeBlamedPeers,
			},
		},
	}
	err = h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round3,
		Body: &Message_Round3{
			Round3: &Round3Msg{
				Delta:        "99",
				BigDelta:     bigDeltaMsg,
				Psidoublepai: psi,
			},
		},
	})
	if err != ErrPairwiseDigestMismatch {
		t.Fatalf("want digest mismatch, got %v", err)
	}
	sign.blamedMu.RLock()
	_, ok := sign.blamedPeers[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestRound3DigestBigDeltaPointMismatchBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r3-bigdelta-mismatch")
	self := "id-0"
	sender := "id-1"
	psi := &paillier.LogStarMessage{}
	want, err := Round3PairwiseDigest(ssid, sender, self, psi)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR3, sender, map[string][]byte{self: want})

	storedDelta := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(3))
	wrongDelta := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(5))
	wrongMsg, err := wrongDelta.ToEcPointMessage()
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
		digestBigDelta: storedDelta,
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
				onBlamedPeers: sign.storeBlamedPeers,
			},
		},
	}
	err = h.HandleMessage(log.New(), &Message{
		Id:   sender,
		Type: Type_Round3,
		Body: &Message_Round3{
			Round3: &Round3Msg{
				Delta:        "42",
				BigDelta:     wrongMsg,
				Psidoublepai: psi,
			},
		},
	})
	if err != ErrPairwiseDigestMismatch {
		t.Fatalf("want digest mismatch, got %v", err)
	}
	sign.blamedMu.RLock()
	_, ok := sign.blamedPeers[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed", sender)
	}
}

func TestSignStartPrepareFailureCallsMsgMainFail(t *testing.T) {
	injected := errors.New("injected prepare failure")
	round1DigestPrepareHook = func(*round1DigestHandler) error { return injected }
	t.Cleanup(func() { round1DigestPrepareHook = nil })

	r1d := &round1DigestHandler{
		round1Handler: &round1Handler{
			peerManager: &staticPM{self: "self"},
		},
	}
	ms := message.NewMsgMain("self", 1, noopStateListener{}, r1d, types.MessageType(Type_Round1Digest))
	sign := &Sign{r1d: r1d, ms: ms, MessageMain: ms}
	sign.Start()
	if ms.GetState() != types.StateFailed {
		t.Fatalf("want StateFailed, got %v", ms.GetState())
	}
}

func TestSignStartPrepareFailureWithoutMsgMain(t *testing.T) {
	round1DigestPrepareHook = func(*round1DigestHandler) error { return errors.New("injected") }
	t.Cleanup(func() { round1DigestPrepareHook = nil })

	mm := &trackingMessageMain{stubMessageMain: stubMessageMain{state: types.StateInit}}
	sign := &Sign{
		r1d:         &round1DigestHandler{round1Handler: &round1Handler{peerManager: &staticPM{self: "self"}}},
		ms:          nil,
		MessageMain: mm,
	}
	sign.Start()
	if mm.started {
		t.Fatal("MessageMain.Start must not run after prepare failure")
	}
}
