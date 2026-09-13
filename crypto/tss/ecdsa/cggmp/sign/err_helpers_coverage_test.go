package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
)

func TestCloneHelpersNil(t *testing.T) {
	if cloneEcPointMsg(nil) != nil {
		t.Fatal("cloneEcPointMsg nil")
	}
	if cloneDecry(nil) != nil {
		t.Fatal("cloneDecry nil")
	}
	if cloneMul(nil) != nil {
		t.Fatal("cloneMul nil")
	}
	if cloneMulStar(nil) != nil {
		t.Fatal("cloneMulStar nil")
	}
	if cloneBytes(nil) != nil {
		t.Fatal("cloneBytes empty should be nil")
	}
	if got := cloneBytes([]byte{1}); len(got) != 1 {
		t.Fatal("cloneBytes copy")
	}
}

func TestParsePeerProductCiphertext(t *testing.T) {
	if _, ok := parsePeerProductCiphertext(nil); ok {
		t.Fatal("empty should fail")
	}
	v, ok := parsePeerProductCiphertext([]byte{0x01, 0x02})
	if !ok || v.Int64() != 0x0102 {
		t.Fatal("unexpected parse")
	}
}

func TestParseErr2Chi(t *testing.T) {
	q := big.NewInt(97)
	if _, ok := parseErr2Chi(nil, q); ok {
		t.Fatal("empty chi should fail")
	}
	if _, ok := parseErr2Chi([]byte{1}, nil); ok {
		t.Fatal("nil q should fail")
	}
	chi, ok := parseErr2Chi([]byte{42}, q)
	if !ok || chi.Int64() != 42 {
		t.Fatal("valid chi should parse")
	}
}

func TestCiphertextEqHelpers(t *testing.T) {
	if ciphertextEqInt(nil, big.NewInt(1)) {
		t.Fatal("nil want should fail")
	}
	if !ciphertextEqInt([]byte{5}, big.NewInt(5)) {
		t.Fatal("int eq should pass")
	}
	if ciphertextEqBytes(nil, []byte{1}) {
		t.Fatal("nil bytes should fail")
	}
	if !ciphertextEqBytes([]byte{7}, []byte{7}) {
		t.Fatal("bytes eq should pass")
	}
}

func TestBlameAbsentSenders(t *testing.T) {
	blamed := map[string]struct{}{}
	blameAbsentSenders("self", map[string]*peer{
		"p1": {},
		"p2": {},
	}, []*Message{{Id: "p1", Type: Type_Err1}}, blamed)
	if _, ok := blamed["p2"]; !ok {
		t.Fatal("missing sender should be blamed")
	}
	if _, ok := blamed["p1"]; ok {
		t.Fatal("present sender should not be blamed")
	}
}

func TestPeerKeysMatch(t *testing.T) {
	if !peerKeysMatch(map[string]struct{}{"a": {}}, map[string]*Err1PeerMsg{"a": {}}) {
		t.Fatal("expected match")
	}
	if peerKeysMatch(map[string]struct{}{"a": {}, "b": {}}, map[string]*Err1PeerMsg{"a": {}}) {
		t.Fatal("expected mismatch on size")
	}
}

func TestErrProductComponents(t *testing.T) {
	if _, ok := errProductComponents(map[string]*Err1PeerMsg{}); ok {
		t.Fatal("empty map should fail")
	}
	components, ok := errProductComponents(map[string]*Err1PeerMsg{
		"p1": {D: []byte{1}, F: []byte{2}},
	})
	if !ok || len(components) != 1 {
		t.Fatal("expected components")
	}
}

func TestReconstructPaillierProduct(t *testing.T) {
	n := big.NewInt(35)
	nSquare := new(big.Int).Mul(n, n)
	h := big.NewInt(11)
	d := big.NewInt(13)
	f := big.NewInt(17)
	fInv := new(big.Int).ModInverse(f, nSquare)
	want := new(big.Int).Mul(h, d)
	want.Mul(want, fInv)
	want.Mod(want, nSquare)
	got, ok := reconstructPaillierProduct(h, nSquare, map[string][2]*big.Int{
		"p1": {d, f},
	})
	if !ok || got.Cmp(want) != 0 {
		t.Fatal("reconstruct mismatch")
	}
}

func TestErrPeerPaillierNs(t *testing.T) {
	ownN := big.NewInt(123)
	peerN := big.NewInt(456)
	out := errPeerPaillierNs("self", ownN, map[string]*peer{
		"p1": {para: paillierzkproof.NewPedersenOpenParameter(peerN, big.NewInt(1), big.NewInt(2))},
	}, map[string]*Err2PeerMsg{"self": {}, "p1": {}})
	if out["self"].Cmp(ownN) != 0 {
		t.Fatal("self N mismatch")
	}
	if out["p1"].Cmp(peerN) != 0 {
		t.Fatal("peer N mismatch")
	}
}

func TestPeerPaillierNs(t *testing.T) {
	n := big.NewInt(99)
	peers := map[string]*peer{
		"p1": {para: paillierzkproof.NewPedersenOpenParameter(n, big.NewInt(1), big.NewInt(2))},
	}
	out := peerPaillierNs(peers)
	if out["p1"].Cmp(n) != 0 {
		t.Fatal("unexpected N")
	}
}

func TestDecModQWitness(t *testing.T) {
	p4, _ := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	body := p4.err2Msg.GetErr2()
	entry := body.Peers[tss.GetTestID(1)]
	if entry == nil || entry.DecModQ == nil {
		t.Fatal("missing err2 peer proof")
	}
	finalC, ok := parsePeerProductCiphertext(entry.ProductCiphertext)
	if !ok {
		t.Fatal("missing product ciphertext")
	}
	curveN := errTestPublicKey.GetCurve().Params().N
	proofX := cggmp.DecModQPublicX(p4.chi, curveN, peerPaillierNs(p4.peers), peerBetaCounts(p4.peers, true))
	_, _, err := decModQWitness(p4.paillierKey, finalC, proofX, curveN)
	if err != nil {
		t.Fatalf("decModQWitness: %v", err)
	}
}

func TestDecModQWitnessDecryptFails(t *testing.T) {
	curveN := errTestPublicKey.GetCurve().Params().N
	_, _, err := decModQWitness(errPaillierKeyA, big.NewInt(1), big.NewInt(1), curveN)
	if err == nil {
		t.Fatal("expected decrypt/lift failure")
	}
}

func TestCloneDecryMulMulStar(t *testing.T) {
	p3, _ := setupRound3PairForErr1Testing(t)
	if err := p3.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	p4, _ := setupRound4PairForErr2Testing(t)
	if err := p4.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	entry := p4.err2Msg.GetErr2().Peers[tss.GetTestID(1)]
	if entry == nil || entry.MulStarProof == nil || entry.DecModQ == nil {
		t.Fatal("missing err2 proofs")
	}
	if cloneMulStar(entry.MulStarProof) == nil {
		t.Fatal("cloneMulStar")
	}
	if cloneDecry(entry.DecModQ) == nil {
		t.Fatal("cloneDecry")
	}
	mul := p3.err1Msg.GetErr1().MulProof
	if mul == nil || cloneMul(mul) == nil {
		t.Fatal("cloneMul")
	}
}

func TestMatchDecModQWithBetaCorrectionEdgeCases(t *testing.T) {
	q := errTestPublicKey.GetCurve().Params().N
	if matchDecModQWithBetaCorrection(nil, []byte("ssid"), big.NewInt(1), big.NewInt(1), big.NewInt(1), q, map[string]*big.Int{"p1": big.NewInt(2)}, errPedZKA) {
		t.Fatal("nil proof should fail")
	}
	peerNs := make(map[string]*big.Int, cggmp.MaxIARemotePeers+1)
	for i := 0; i <= cggmp.MaxIARemotePeers; i++ {
		peerNs[tss.GetTestID(i)] = big.NewInt(int64(i + 2))
	}
	if matchDecModQWithBetaCorrection(&paillierzkproof.DecModQMessage{}, []byte("ssid"), big.NewInt(1), big.NewInt(1), big.NewInt(1), q, peerNs, errPedZKA) {
		t.Fatal("too many peers should fail")
	}
}

func TestParseErr2ChiOutOfRange(t *testing.T) {
	q := big.NewInt(97)
	if _, ok := parseErr2Chi([]byte{255}, q); ok {
		t.Fatal("chi >= q should fail")
	}
}

func TestReconstructPaillierProductInvalid(t *testing.T) {
	if _, ok := reconstructPaillierProduct(nil, big.NewInt(35), map[string][2]*big.Int{}); ok {
		t.Fatal("nil h should fail")
	}
}

func TestPeerKeysMatchNilEntry(t *testing.T) {
	if peerKeysMatch(map[string]struct{}{"a": {}}, map[string]*Err1PeerMsg{"a": nil}) {
		t.Fatal("nil entry should fail")
	}
}

func TestCloneEcPointMsgCopies(t *testing.T) {
	src := &pt.EcPointMessage{Curve: 1, X: []byte("x"), Y: []byte("y")}
	cloned := cloneEcPointMsg(src)
	src.X[0] ^= 0xff
	if cloned.GetX()[0] == src.X[0] {
		t.Fatal("clone should be independent")
	}
}
