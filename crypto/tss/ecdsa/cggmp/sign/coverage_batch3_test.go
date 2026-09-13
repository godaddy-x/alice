package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

func TestRound1FinalizeSuccess(t *testing.T) {
	ssid := []byte("r1-finalize-ok")
	self := tss.GetTestID(0)
	peerID := tss.GetTestID(1)
	pm := &recordPM{staticPM: staticPM{self: self}}

	kSelf := big.NewInt(5)
	gammaSelf := big.NewInt(11)
	muSelf := big.NewInt(2)
	rhoSelf := big.NewInt(3)
	kPeer := big.NewInt(2)
	gammaPeer := big.NewInt(10)
	rhoPeer := big.NewInt(7)

	kCipherSelf, _, err := errPaillierKeyA.EncryptWithOutputSalt(kSelf)
	if err != nil {
		t.Fatal(err)
	}
	gCipherSelf, _, err := errPaillierKeyA.EncryptWithOutputSalt(gammaSelf)
	if err != nil {
		t.Fatal(err)
	}
	kCipherPeer, _, err := errPaillierKeyB.EncryptWithOutputSalt(kPeer)
	if err != nil {
		t.Fatal(err)
	}
	gCipherPeer, _, err := errPaillierKeyB.EncryptWithOutputSalt(gammaPeer)
	if err != nil {
		t.Fatal(err)
	}

	peerNode := newErrTestPeer(peerID, ssid, errPedZKB)
	psi, err := paillierzkproof.NewEncryptRangeMessage(
		parameter, ssid, kCipherPeer, errPedZKB.GetN(), kPeer, rhoPeer, errPedZKB,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := peerNode.AddMessage(&Message{
		Id: peerID, Type: Type_Round1,
		Body: &Message_Round1{
			Round1: &Round1Msg{
				KCiphertext:     kCipherPeer.Bytes(),
				GammaCiphertext: gCipherPeer.Bytes(),
				Psi:             psi,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	share := big.NewInt(2)
	bkCoeff := big.NewInt(2)
	bkMulShare := new(big.Int).Mul(share, bkCoeff)
	bkPartial := errTestG.ScalarMult(share).ScalarMult(bkCoeff)

	h := &round1Handler{
		ssid:              ssid,
		pubKey:            errTestPublicKey,
		paillierKey:       errPaillierKeyA,
		k:                 kSelf,
		rho:               rhoSelf,
		mu:                muSelf,
		gamma:             gammaSelf,
		kCiphertext:       kCipherSelf,
		gammaCiphertext:   gCipherSelf,
		bkMulShare:        bkMulShare,
		bkpartialPubKey:   bkPartial,
		msg:               []byte("test-msg"),
		own:               newErrTestPeer(self, ssid, errPedZKA),
		peers:             map[string]*peer{peerID: peerNode},
		peerManager:       pm,
		peerNum:           1,
	}
	next, err := h.Finalize(log.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := next.(*round2DigestHandler); !ok {
		t.Fatal("expected round2DigestHandler")
	}
	if peerNode.round1Data == nil || peerNode.round1Data.round2Msg == nil {
		t.Fatal("expected pending round2 message")
	}
	if len(pm.sent) != 1 || pm.sent[0] != peerID {
		t.Fatalf("expected Round2 digest broadcast, got %v", pm.sent)
	}
}

func TestRound2DigestGammaWrongPointBlamesSender(t *testing.T) {
	ssid := []byte("ssid-r2-wrong-gamma")
	self := "id-0"
	sender := "id-1"
	r2 := &Round2Msg{D: []byte{1}, F: []byte{2}, Dhat: []byte{3}, Fhat: []byte{4}}
	want, err := Round2PairwiseDigest(ssid, sender, self, r2)
	if err != nil {
		t.Fatal(err)
	}
	store := newPairwiseDigestStore()
	store.SetFinalized(digestR2, sender, map[string][]byte{self: want})

	revealGamma := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(2))
	storedGamma := pt.ScalarBaseMult(errTestPublicKey.GetCurve(), big.NewInt(3))
	gammaMsg, err := revealGamma.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	r2.Gamma = gammaMsg

	sign := &Sign{}
	h := &round2Handler{
		round1Handler: &round1Handler{
			ssid:        ssid,
			digestStore: store,
			peers: map[string]*peer{
				sender: {
					Peer:          message.NewPeer(sender),
					digestGamma:   storedGamma,
				},
			},
			peerManager:   &staticPM{self: self},
			onBlamedPeers: sign.storeBlamedPeers,
		},
	}
	err = h.HandleMessage(log.New(), &Message{Id: sender, Type: Type_Round2, Body: &Message_Round2{Round2: r2}})
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

func TestProcessErr1MsgBlamesGDeltaAggregateMismatch(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	p3.BigDelta = errTestG.ScalarMult(big.NewInt(99999))
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected remote sender blamed for gDelta aggregate mismatch")
	}
}

func TestProcessErr1MsgBlamesTamperedF(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	entry := remote.GetErr1().Peers[tss.GetTestID(0)]
	if entry == nil || len(entry.F) == 0 {
		t.Fatal("missing F in err1 peer entry")
	}
	entry.F[0] ^= 0xff
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for tampered F")
	}
}

func TestProcessErr1MsgBlamesProductCiphertextMismatch(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	entry := remote.GetErr1().Peers[tss.GetTestID(0)]
	if entry == nil || len(entry.ProductCiphertext) == 0 {
		t.Fatal("missing product ciphertext")
	}
	entry.ProductCiphertext[0] ^= 0xff
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for product ciphertext mismatch")
	}
}

func TestProcessErr1MsgAggregateBigDeltaAddCurveMismatch(t *testing.T) {
	p3, _, remote := buildErr1Messages(t)
	round3Msg := p3.peers[tss.GetTestID(1)].GetMessage(types.MessageType(Type_Round3))
	if round3Msg == nil {
		t.Fatal("missing round3 message")
	}
	wrongCurve, err := pt.ScalarBaseMult(elliptic.P256(), big.NewInt(1)).ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	getMessage(round3Msg).GetRound3().BigDelta = wrongCurve
	blamed, err := p3.ProcessErr1Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	// Per-sender verification passes; aggregate Add fails with deltaOK=false (no gDelta blame).
	if len(blamed) != 0 {
		t.Fatalf("expected no blame when aggregate Add fails early, got %v", blamed)
	}
}

func TestBuildErr1PeerMsgsFailsOnWitnessMismatch(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	if err := p3.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	curveN := errTestPublicKey.GetCurve().Params().N
	body := p3.err1Msg.GetErr1()
	entry := body.Peers[tss.GetTestID(1)]
	if entry == nil {
		t.Fatal("missing err1 peer entry")
	}
	finalC, ok := parsePeerProductCiphertext(entry.ProductCiphertext)
	if !ok {
		t.Fatal("missing product ciphertext")
	}
	proofX := cggmp.DecModQPublicX(p3.delta, curveN, peerPaillierNs(p3.peers), peerBetaCounts(p3.peers, false))
	y, salt, err := decModQWitness(p3.paillierKey, finalC, proofX, curveN)
	if err != nil {
		t.Fatal(err)
	}
	badY := new(big.Int).Add(y, big.NewInt(1))
	if _, err := buildErr1PeerMsgs(p3, badY, salt, finalC, proofX); err == nil {
		t.Fatal("expected buildErr1PeerMsgs failure on witness mismatch")
	}
}
