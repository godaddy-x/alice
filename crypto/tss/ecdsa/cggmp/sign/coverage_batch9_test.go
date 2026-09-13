package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

func TestRound2HandleMessagePsiVerifyFailure(t *testing.T) {
	ssid := []byte("ssid-r2-psi-fail")
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
	r2 := &Round2Msg{
		D:     dBytes,
		F:     fBytes.Bytes(),
		Psi:   psiProof,
		Gamma: gammaMsg,
	}
	want, err := Round2PairwiseDigest(ssid, sender, self, r2)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: want})
	r2.Psi = &paillierzkproof.PaillierAffAndGroupRangeMessage{S: []byte{0xff}}

	h := &round2Handler{
		round1Handler: &round1Handler{
			ssid:        ssid,
			pubKey:      errTestPublicKey,
			digestStore: store,
			peers: map[string]*peer{
				sender: {
					Peer:        message.NewPeer(sender),
					para:        errPedZKB,
					ssidWithBk:  ssid,
					digestGamma: Gamma,
					round1Data:  &round1Data{kCiphertext: kCipher},
				},
			},
			peerManager: &staticPM{self: self},
			own:         &peer{para: errPedZKA, ssidWithBk: ssid},
			paillierKey: errPaillierKeyA,
			kCiphertext: kCipher,
		},
	}
	if err := h.HandleMessage(log.New(), &Message{Id: sender, Type: Type_Round2, Body: &Message_Round2{Round2: r2}}); err == nil {
		t.Fatal("expected Psi verify error")
	}
}
