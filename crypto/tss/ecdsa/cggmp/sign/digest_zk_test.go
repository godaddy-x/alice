package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

func TestRound1InvalidPsiVerifyBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r1-zk")
	self := "id-0"
	sender := "id-1"
	kBytes := []byte("k-cipher")
	gBytes := []byte("g-cipher")
	invalidPsi := &paillier.EncryptRangeMessage{S: []byte{0xff}}

	want, err := Round1PsiDigest(ssid, sender, self, invalidPsi)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR1, sender, map[string][]byte{self: want})

	sign := &Sign{}
	peerNode := &peer{
		Peer:                  message.NewPeer(sender),
		para:                  errPedZKB,
		ssidWithBk:            ssid,
		digestKCiphertext:     append([]byte(nil), kBytes...),
		digestGammaCiphertext: append([]byte(nil), gBytes...),
	}
	h := &round1Handler{
		ssid:          ssid,
		digestStore:   store,
		peers:         map[string]*peer{sender: peerNode},
		peerManager:   &staticPM{self: self},
		own:           &peer{para: errPedZKA, ssidWithBk: ssid},
		onBlame: sign.storeBlame,
	}
	msg := &Message{
		Id:   sender,
		Type: Type_Round1,
		Body: &Message_Round1{
			Round1: &Round1Msg{
				KCiphertext:     append([]byte(nil), kBytes...),
				GammaCiphertext: append([]byte(nil), gBytes...),
				Psi:             invalidPsi,
			},
		},
	}
	err = h.HandleMessage(log.New(), msg)
	if err == nil {
		t.Fatal("expected ZK verify error")
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed after invalid psi", sender)
	}
}

func TestRound2InvalidPsiVerifyBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r2-zk")
	self := "id-0"
	sender := "id-1"
	gamma := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(7))
	gammaMsg, err := gamma.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	r2 := &Round2Msg{
		D:    []byte{1},
		F:    []byte{2},
		Dhat: []byte{3},
		Fhat: []byte{4},
		Psi:  &paillier.PaillierAffAndGroupRangeMessage{S: []byte{0xff}},
	}
	want, err := Round2PairwiseDigest(ssid, sender, self, r2)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: want})

	sign := &Sign{}
	kCipher, _, err := errPaillierKeyA.EncryptWithOutputSalt(big.NewInt(5))
	if err != nil {
		t.Fatal(err)
	}
	peerNode := &peer{
		Peer:        message.NewPeer(sender),
		para:        errPedZKB,
		ssidWithBk:  ssid,
		digestGamma: gamma,
		round1Data:  &round1Data{kCiphertext: kCipher},
	}
	h := &round2Handler{
		round1Handler: &round1Handler{
			ssid:          ssid,
			digestStore:   store,
			peers:         map[string]*peer{sender: peerNode},
			peerManager:   &staticPM{self: self},
			own:           &peer{para: errPedZKA, ssidWithBk: ssid},
			paillierKey:   errPaillierKeyA,
			kCiphertext:   kCipher,
			onBlame: sign.storeBlame,
		},
	}
	r2.Gamma = gammaMsg
	msg := &Message{Id: sender, Type: Type_Round2, Body: &Message_Round2{Round2: r2}}
	err = h.HandleMessage(log.New(), msg)
	if err == nil {
		t.Fatal("expected ZK verify error")
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed after invalid psi", sender)
	}
}

func TestRound3InvalidPsiVerifyBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r3-zk")
	self := "id-0"
	sender := "id-1"
	psi := &paillier.LogStarMessage{S: []byte{0xff}}
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
		Peer:            message.NewPeer(sender),
		para:            errPedZKB,
		ssidWithBk:      ssid,
		digestDelta:     "42",
		digestBigDelta:  bigDelta,
		round1Data:      &round1Data{kCiphertext: kCipher},
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
	msg := &Message{
		Id:   sender,
		Type: Type_Round3,
		Body: &Message_Round3{
			Round3: &Round3Msg{
				Delta:        "42",
				BigDelta:     bigDeltaMsg,
				Psidoublepai: psi,
			},
		},
	}
	err = h.HandleMessage(log.New(), msg)
	if err == nil {
		t.Fatal("expected ZK verify error")
	}
	sign.blamedMu.RLock()
	_, ok := sign.blameUnion()[sender]
	sign.blamedMu.RUnlock()
	if !ok {
		t.Fatalf("expected %s blamed after invalid psidoublepai", sender)
	}
}
