package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
)

func TestAttachErr2DecModQKmSkipsNilPeerEntry(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	curveN := errTestPublicKey.GetCurve().Params().N
	entry := p4.err2Msg.GetErr2().Peers[tss.GetTestID(1)]
	if entry == nil || entry.DecModQ == nil {
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
	peersMsg := map[string]*Err2PeerMsg{
		tss.GetTestID(1): {DecModQ: entry.DecModQ},
	}
	if err := attachErr2DecModQ(p4, y, salt, finalC, proofX, peersMsg); err != nil {
		t.Fatal(err)
	}
	km := new(big.Int).Exp(p4.kCiphertext, new(big.Int).SetBytes(p4.msg), p4.paillierKey.GetNSquare())
	xKm := new(big.Int).Mul(p4.R.GetX(), p4.chi)
	xKm.Sub(p4.sigma, xKm)
	xKm.Mod(xKm, curveN)
	yKm, saltKm, err := decModQWitness(p4.paillierKey, km, xKm, curveN)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachErr2DecModQKm(p4, yKm, saltKm, km, xKm, map[string]*Err2PeerMsg{}); err != nil {
		t.Fatal(err)
	}
	if err := attachErr2DecModQKm(p4, yKm, saltKm, km, xKm, peersMsg); err != nil {
		t.Fatal(err)
	}
	if peersMsg[tss.GetTestID(1)].DecModQKm == nil {
		t.Fatal("expected DecModQKm on present entry")
	}
}

func TestAttachErr2DecModQFailsOnBadPeerPed(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	curveN := errTestPublicKey.GetCurve().Params().N
	entry := p4.err2Msg.GetErr2().Peers[tss.GetTestID(1)]
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
	peersMsg := map[string]*Err2PeerMsg{
		tss.GetTestID(1): {},
	}
	if err := attachErr2DecModQ(p4, badY, salt, finalC, proofX, peersMsg); err == nil {
		t.Fatal("expected attachErr2DecModQ failure on witness/mod-q mismatch")
	}
}

func TestBlameAbsentSendersSkipsSelf(t *testing.T) {
	blamed := map[string]struct{}{}
	blameAbsentSenders("self", map[string]*peer{
		"self": {},
		"p1":   {},
	}, nil, blamed)
	if _, ok := blamed["self"]; ok {
		t.Fatal("self should never be blamed as absent sender")
	}
	if _, ok := blamed["p1"]; !ok {
		t.Fatal("expected remote peer blamed")
	}
}

func TestReconstructPaillierProductNilComponentField(t *testing.T) {
	nSquare := new(big.Int).Mul(big.NewInt(35), big.NewInt(35))
	_, ok := reconstructPaillierProduct(big.NewInt(11), nSquare, map[string][2]*big.Int{
		"p1": {big.NewInt(3), nil},
	})
	if ok {
		t.Fatal("expected failure when f is nil")
	}
}

func TestErrProductComponentsNilMapEntry(t *testing.T) {
	_, ok := errProductComponents(map[string]*Err1PeerMsg{
		"p1": nil,
	})
	if ok {
		t.Fatal("expected failure for nil map entry")
	}
}

func TestNewRound1HandlerRejectsNilPed(t *testing.T) {
	self := tss.GetTestID(0)
	peer := tss.GetTestID(1)
	pub := errTestPublicKey
	bks := map[string]*birkhoffinterpolation.BkParameter{
		self: birkhoffinterpolation.NewBkParameter(big.NewInt(1), 0),
		peer: birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0),
	}
	partial := map[string]*pt.ECPoint{self: pub, peer: pub}
	ped := map[string]*paillierzkproof.PederssenOpenParameter{
		self: errPedZKA,
		peer: nil,
	}
	pm := tss.NewTestPeerManager(0, 2)
	_, err := newRound1Handler(2, []byte("ssid"), big.NewInt(1), pub, partial, errPaillierKeyA, ped, bks, []byte("msg"), pm)
	if err == nil {
		t.Fatal("expected nil ped validation error")
	}
}
