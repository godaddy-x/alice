package sign

import (
	"math/big"
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

func enrichPeerForRound2Finalize(peer *peer) {
	if peer == nil {
		return
	}
	if peer.round1Data != nil && peer.round1Data.betahat == nil && peer.round1Data.beta != nil {
		peer.round1Data.betahat = new(big.Int).Set(peer.round1Data.beta)
	}
	if peer.round2Data != nil && peer.round2Data.dhat == nil && peer.round2Data.d != nil {
		peer.round2Data.dhat = new(big.Int).Set(peer.round2Data.d)
	}
}

func prepareRound2ForFinalize(p2 *round2Handler) {
	if p2.bkMulShare == nil {
		p2.bkMulShare = big.NewInt(4)
	}
	for _, peer := range p2.peers {
		enrichPeerForRound2Finalize(peer)
	}
}

func setupRound2PairForFinalizeTesting(t *testing.T) (*round2Handler, *round2Handler) {
	t.Helper()
	p3, p2 := setupRound3PairForErr1Testing(t)
	prepareRound2ForFinalize(p3.round2Handler)
	prepareRound2ForFinalize(p2.round2Handler)
	return p3.round2Handler, p2.round2Handler
}

func setupRound3PairForFinalizeTesting(t *testing.T) (*round3Handler, *round3Handler) {
	t.Helper()
	return setupRound3PairForErr1Testing(t)
}

func TestRound2FinalizeDecryptDFails(t *testing.T) {
	p2, _ := setupRound2PairForFinalizeTesting(t)
	peer := p2.peers[tss.GetTestID(1)]
	// Ciphertext must be in [0, n^2); values outside fail isCorrectCiphertext.
	peer.round2Data.d = new(big.Int).Lsh(p2.paillierKey.GetNSquare(), 1)
	_, err := p2.Finalize(log.New())
	if err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestRound2FinalizeSumGammaAddFails(t *testing.T) {
	p2, _ := setupRound2PairForFinalizeTesting(t)
	wrongCurve := elliptic.P256()
	p2.peers[tss.GetTestID(1)].round2Data.allGammaPoint = pt.ScalarBaseMult(wrongCurve, big.NewInt(3))
	_, err := p2.Finalize(log.New())
	if err == nil {
		t.Fatal("expected sumGamma add error")
	}
}

func TestRound2FinalizeDecryptDhatFails(t *testing.T) {
	p2, _ := setupRound2PairForFinalizeTesting(t)
	peer := p2.peers[tss.GetTestID(1)]
	peer.round2Data.dhat = new(big.Int).Lsh(p2.paillierKey.GetNSquare(), 1)
	_, err := p2.Finalize(log.New())
	if err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestRound2FinalizeSumGammaIdentity(t *testing.T) {
	p2, _ := setupRound2PairForFinalizeTesting(t)
	curve := errTestPublicKey.GetCurve()
	p2.gamma = big.NewInt(0)
	identity := pt.NewIdentity(curve)
	p2.peers[tss.GetTestID(1)].round2Data.allGammaPoint = identity
	_, err := p2.Finalize(log.New())
	if err != ErrZeroR {
		t.Fatalf("want ErrZeroR, got %v", err)
	}
}

func TestRound3FinalizeBigDeltaToPointFails(t *testing.T) {
	p3, _ := setupRound3PairForFinalizeTesting(t)
	round3Msg := p3.peers[tss.GetTestID(1)].GetMessage(types.MessageType(Type_Round3))
	if round3Msg == nil {
		t.Fatal("missing round3 message")
	}
	getMessage(round3Msg).GetRound3().BigDelta = &pt.EcPointMessage{Curve: 999, X: []byte{1}, Y: []byte{2}}
	_, err := p3.Finalize(log.New())
	if err == nil {
		t.Fatal("expected ToPoint error")
	}
}

func TestRound3FinalizeBigDeltaAddFails(t *testing.T) {
	p3, _ := setupRound3PairForFinalizeTesting(t)
	round3Msg := p3.peers[tss.GetTestID(1)].GetMessage(types.MessageType(Type_Round3))
	if round3Msg == nil {
		t.Fatal("missing round3 message")
	}
	wrongCurve := elliptic.P256()
	wrongPoint := pt.ScalarBaseMult(wrongCurve, big.NewInt(3))
	wrongMsg, err := wrongPoint.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	getMessage(round3Msg).GetRound3().BigDelta = wrongMsg
	_, err = p3.Finalize(log.New())
	if err == nil {
		t.Fatal("expected bigDelta add error")
	}
}

func TestRound3FinalizeZeroR(t *testing.T) {
	p3, _ := setupRound3PairForFinalizeTesting(t)
	p3.sumGamma = pt.NewIdentity(errTestPublicKey.GetCurve())
	_, err := p3.Finalize(log.New())
	if err != ErrZeroR {
		t.Fatalf("want ErrZeroR, got %v", err)
	}
}
