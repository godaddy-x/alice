package sign

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

func TestProcessErr1MsgAggregateRound3ToPointError(t *testing.T) {
	handlers, errMsgs := setupErr1ThreePartyTesting(t)
	h := handlers[0]
	round3Msg := h.peers[tss.GetTestID(1)].GetMessage(types.MessageType(Type_Round3))
	if round3Msg == nil {
		t.Fatal("missing round3 message")
	}
	getMessage(round3Msg).GetRound3().BigDelta = &pt.EcPointMessage{Curve: 999, X: []byte{1}, Y: []byte{2}}
	blamed, err := h.ProcessErr1Msg([]*Message{errMsgs[1], errMsgs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected local peer blamed when aggregate BigDelta ToPoint fails")
	}
}

func TestProcessErr1MsgAggregateRound3NilBody(t *testing.T) {
	handlers, errMsgs := setupErr1ThreePartyTesting(t)
	h := handlers[0]
	round3Msg := h.peers[tss.GetTestID(2)].GetMessage(types.MessageType(Type_Round3))
	if round3Msg == nil {
		t.Fatal("missing round3 message")
	}
	getMessage(round3Msg).Body = nil
	blamed, err := h.ProcessErr1Msg([]*Message{errMsgs[1], errMsgs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(2)]; !ok {
		t.Fatal("expected local peer blamed when round3 body is nil")
	}
}

func TestProcessErr1MsgThreePartyBlamesNilErr1Body(t *testing.T) {
	handlers, _ := setupErr1ThreePartyTesting(t)
	h := handlers[0]
	bad := &Message{Id: tss.GetTestID(1), Type: Type_Err1, Body: nil}
	blamed, err := h.ProcessErr1Msg([]*Message{
		bad,
		{Id: tss.GetTestID(2), Type: Type_Err1, Body: handlers[2].err1Msg.Body},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for nil err1 body")
	}
}

func TestProcessErr2MsgThreePartyBlamesBadChi(t *testing.T) {
	handlers, errMsgs := setupErr2ThreePartyTesting(t)
	h := handlers[0]
	curveN := errTestPublicKey.GetCurve().Params().N
	errMsgs[1].GetErr2().Chi = new(big.Int).Mod(big.NewInt(999999), curveN).Bytes()
	blamed, err := h.ProcessErr2Msg([]*Message{errMsgs[1], errMsgs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed for bad chi")
	}
}

func TestProcessErr2MsgThreePartySkipsSelf(t *testing.T) {
	handlers, errMsgs := setupErr2ThreePartyTesting(t)
	h := handlers[0]
	selfMsg := &Message{Id: tss.GetTestID(0), Type: Type_Err2, Body: errMsgs[0].Body}
	blamed, err := h.ProcessErr2Msg([]*Message{selfMsg, errMsgs[1], errMsgs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if len(blamed) != 0 {
		t.Fatalf("expected no blame when only remotes are valid, got %v", blamed)
	}
}

func TestRound2HandleMessageGammaToPointError(t *testing.T) {
	p2, _ := setupRound2PairForFinalizeTesting(t)
	err := p2.HandleMessage(log.New(), &Message{
		Id:   tss.GetTestID(1),
		Type: Type_Round2,
		Body: &Message_Round2{
			Round2: &Round2Msg{
				Gamma: &pt.EcPointMessage{Curve: 999, X: []byte{1}, Y: []byte{2}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected Gamma ToPoint error")
	}
}

func TestErrProductComponentsErr2NilEntry(t *testing.T) {
	_, ok := errProductComponents(map[string]*Err2PeerMsg{
		"p1": nil,
	})
	if ok {
		t.Fatal("expected failure on nil err2 entry")
	}
}

func TestErrProductComponentsErr2EmptyF(t *testing.T) {
	_, ok := errProductComponents(map[string]*Err2PeerMsg{
		"p1": {D: []byte{1}, F: nil},
	})
	if ok {
		t.Fatal("expected failure on empty F")
	}
}

func TestAttachErr2DecModQKmWitnessMismatch(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	curveN := errTestPublicKey.GetCurve().Params().N
	km := new(big.Int).Exp(p4.kCiphertext, new(big.Int).SetBytes(p4.msg), p4.paillierKey.GetNSquare())
	xKm := new(big.Int).Mul(p4.R.GetX(), p4.chi)
	xKm.Sub(p4.sigma, xKm)
	xKm.Mod(xKm, curveN)
	yKm, saltKm, err := decModQWitness(p4.paillierKey, km, xKm, curveN)
	if err != nil {
		t.Fatal(err)
	}
	badY := new(big.Int).Add(yKm, big.NewInt(1))
	peersMsg := map[string]*Err2PeerMsg{tss.GetTestID(1): {}}
	if err := attachErr2DecModQKm(p4, badY, saltKm, km, xKm, peersMsg); err == nil {
		t.Fatal("expected attachErr2DecModQKm failure on witness mismatch")
	}
}

func TestNewSignInvalidBkThreshold(t *testing.T) {
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
	_, err := NewSign(99, []byte("ssid"), big.NewInt(1), pub, partial, errPaillierKeyA, ped, bks, []byte("msg"), pm, noopStateListener{})
	if err == nil {
		t.Fatal("expected NewSign failure on invalid bk threshold")
	}
}
