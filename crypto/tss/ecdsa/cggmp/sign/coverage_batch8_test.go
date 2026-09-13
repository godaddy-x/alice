package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

func TestOnAbortErr1BuildFailure(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	curveN := errTestPublicKey.GetCurve().Params().N
	p3.delta = new(big.Int).Mod(big.NewInt(999999), curveN)
	_, err := p3.onAbortErr1(log.New(), nil)
	if err == nil {
		t.Fatal("expected onAbortErr1 failure when err1 payload cannot be built")
	}
}

func TestOnAbortErr2BuildFailure(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	curveN := errTestPublicKey.GetCurve().Params().N
	p4.chi = new(big.Int).Mod(big.NewInt(999999), curveN)
	_, err := p4.onAbortErr2(log.New(), nil)
	if err == nil {
		t.Fatal("expected onAbortErr2 failure when err2 payload cannot be built")
	}
}

func TestEnterErr1PhaseBuildFailure(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	curveN := errTestPublicKey.GetCurve().Params().N
	p3.delta = new(big.Int).Mod(big.NewInt(999999), curveN)
	_, err := p3.enterErr1Phase(log.New(), ErrInvalidDelta)
	if err == nil {
		t.Fatal("expected enterErr1Phase failure when err1 payload cannot be built")
	}
}

func TestEnterErr2PhaseBuildFailure(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	curveN := errTestPublicKey.GetCurve().Params().N
	p4.chi = new(big.Int).Mod(big.NewInt(999999), curveN)
	_, err := p4.enterErr2Phase(log.New(), ErrIncorrectSig)
	if err == nil {
		t.Fatal("expected enterErr2Phase failure when err2 payload cannot be built")
	}
}

func TestProcessErr2MsgBlamesMissingDecModQKmProof(t *testing.T) {
	p4, _, remote := buildErr2Messages(t)
	entry := remote.GetErr2().Peers[tss.GetTestID(0)]
	if entry == nil {
		t.Fatal("missing peer entry")
	}
	entry.DecModQKm = nil
	blamed, err := p4.ProcessErr2Msg([]*Message{remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for missing DecModQKm")
	}
}

func TestAttachErr2DecModQWitnessMismatch(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	curveN := errTestPublicKey.GetCurve().Params().N
	body := p4.err2Msg.GetErr2()
	entry := body.Peers[tss.GetTestID(1)]
	if entry == nil {
		t.Fatal("missing err2 peer entry")
	}
	finalC, ok := parsePeerProductCiphertext(entry.ProductCiphertext)
	if !ok {
		t.Fatal("missing product ciphertext")
	}
	proofX := cggmp.DecModQPublicX(p4.chi, curveN, peerPaillierNs(p4.peers), peerBetaCounts(p4.peers, true))
	y, salt, err := decModQWitness(p4.paillierKey, finalC, proofX, curveN)
	if err != nil {
		t.Fatal(err)
	}
	badY := new(big.Int).Add(y, big.NewInt(1))
	peersMsg := map[string]*Err2PeerMsg{tss.GetTestID(1): {}}
	if err := attachErr2DecModQ(p4, badY, salt, finalC, proofX, peersMsg); err == nil {
		t.Fatal("expected attachErr2DecModQ failure on witness mismatch")
	}
}

func TestNewRound1HandlerInvalidPublicKey(t *testing.T) {
	curve := elliptic.Secp256k1()
	pub := pt.ScalarBaseMult(curve, big.NewInt(1))
	wrongPub := pt.ScalarBaseMult(curve, big.NewInt(2))
	self := tss.GetTestID(0)
	peer := tss.GetTestID(1)
	bks := map[string]*birkhoffinterpolation.BkParameter{
		self: birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0),
		peer: birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0),
	}
	partial := map[string]*pt.ECPoint{self: wrongPub, peer: wrongPub}
	ped := map[string]*paillierzkproof.PederssenOpenParameter{
		self: errPedZKA,
		peer: errPedZKB,
	}
	pm := tss.NewTestPeerManager(0, 2)
	_, err := newRound1Handler(2, []byte("ssid"), big.NewInt(1), pub, partial, errPaillierKeyA, ped, bks, []byte("msg"), pm)
	if err == nil {
		t.Fatal("expected ValidatePublicKey failure")
	}
}

func TestProcessErr1MsgAggregateRound3InnerNil(t *testing.T) {
	handlers, errMsgs := setupErr1ThreePartyTesting(t)
	h := handlers[0]
	round3Msg := h.peers[tss.GetTestID(1)].GetMessage(types.MessageType(Type_Round3))
	if round3Msg == nil {
		t.Fatal("missing round3 message")
	}
	getMessage(round3Msg).Body = &Message_Round3{Round3: nil}
	blamed, err := h.ProcessErr1Msg([]*Message{errMsgs[1], errMsgs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected local peer blamed when round3 inner message is nil")
	}
}

func TestProcessErr2MsgBlamesMissingRound2Data(t *testing.T) {
	handlers, errMsgs := setupErr2ThreePartyTesting(t)
	h := handlers[0]
	h.peers[tss.GetTestID(1)].round2Data = nil
	blamed, err := h.ProcessErr2Msg([]*Message{errMsgs[1], errMsgs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for missing round2 data")
	}
}
