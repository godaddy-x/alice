package signer

import (
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/tss/pairwise"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types/mocks"
)

func TestRound1PairwiseDigestStable(t *testing.T) {
	curve := elliptic.Ed25519()
	d := ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(3))
	e := ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(5))
	ssid := []byte("ssid")
	bkX := []byte{1, 2, 3}
	d1, err := Round1PairwiseDigest(ssid, "a", "b", bkX, d, e)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Round1PairwiseDigest(ssid, "a", "b", bkX, d, e)
	if err != nil {
		t.Fatal(err)
	}
	if string(d1) != string(d2) {
		t.Fatal("digest not stable")
	}
	d3, err := Round1PairwiseDigest(ssid, "a", "c", bkX, d, e)
	if err != nil {
		t.Fatal(err)
	}
	if string(d1) == string(d3) {
		t.Fatal("recipient should change digest")
	}
}

func TestValidateDigestTableCrossPeer(t *testing.T) {
	curve := elliptic.Ed25519()
	expPublic := ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(100))
	ss := [][]*big.Int{
		{big.NewInt(1), big.NewInt(102), big.NewInt(0)},
		{big.NewInt(2), big.NewInt(104), big.NewInt(0)},
	}
	bks := map[string]*birkhoffinterpolation.BkParameter{
		tss.GetTestID(0): birkhoffinterpolation.NewBkParameter(ss[0][0], 0),
		tss.GetTestID(1): birkhoffinterpolation.NewBkParameter(ss[1][0], 0),
	}
	Ys := map[string]*ecpointgrouplaw.ECPoint{
		tss.GetTestID(0): ecpointgrouplaw.ScalarBaseMult(curve, ss[0][1]),
		tss.GetTestID(1): ecpointgrouplaw.ScalarBaseMult(curve, ss[1][1]),
	}
	msg := utils.Pad([]byte("8077818"), 32)
	pm0 := tss.NewTestPeerManager(0, 2)
	s0, err := NewSigner(expPublic, pm0, 2, ss[0][1], &dkg.Result{Bks: bks, Ys: Ys}, msg, new(mocks.StateChangedListener))
	if err != nil {
		t.Fatal(err)
	}
	if err := s0.ph.prepareRound1Digest(); err != nil {
		t.Fatal(err)
	}
	body := s0.ph.digestMsg.GetRound1Digest()

	pm1 := tss.NewTestPeerManager(1, 2)
	s1, err := NewSigner(expPublic, pm1, 2, ss[1][1], &dkg.Result{Bks: bks, Ys: Ys}, msg, new(mocks.StateChangedListener))
	if err != nil {
		t.Fatal(err)
	}
	exp := s1.ph.expectedPeersForSender(tss.GetTestID(0))
	if _, err := validateDigestTable(s1.ph.ssid, tagR1, tss.GetTestID(0), exp, body.GetToPeer(), body.GetTableRoot()); err != nil {
		t.Fatalf("cross validate: %v", err)
	}
}

func TestGateDigestBarrierBlames(t *testing.T) {
	curve := elliptic.Ed25519()
	expPublic := ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(100))
	ss := [][]*big.Int{{big.NewInt(1), big.NewInt(102), big.NewInt(0)}, {big.NewInt(2), big.NewInt(104), big.NewInt(0)}}
	bks := map[string]*birkhoffinterpolation.BkParameter{
		tss.GetTestID(0): birkhoffinterpolation.NewBkParameter(ss[0][0], 0),
		tss.GetTestID(1): birkhoffinterpolation.NewBkParameter(ss[1][0], 0),
	}
	Ys := map[string]*ecpointgrouplaw.ECPoint{
		tss.GetTestID(0): ecpointgrouplaw.ScalarBaseMult(curve, ss[0][1]),
		tss.GetTestID(1): ecpointgrouplaw.ScalarBaseMult(curve, ss[1][1]),
	}
	msg := utils.Pad([]byte("8077818"), 32)
	pm0 := tss.NewTestPeerManager(0, 2)
	blamed := map[string]struct{}{}
	s0, err := NewSigner(expPublic, pm0, 2, ss[0][1], &dkg.Result{Bks: bks, Ys: Ys}, msg, new(mocks.StateChangedListener))
	if err != nil {
		t.Fatal(err)
	}
	s0.ph.onBlame = func(c cggmp.BlameContribution) {
		for k := range c.Union() {
			blamed[k] = struct{}{}
		}
	}
	err = s0.ph.gateEdgeDigest(pairwise.Round1, tss.GetTestID(1), tss.GetTestID(0), func() ([]byte, error) {
		return make([]byte, 32), nil
	})
	if err != pairwise.ErrDigestBarrier {
		t.Fatalf("expected barrier, got %v", err)
	}
	if _, ok := blamed[tss.GetTestID(1)]; !ok {
		t.Fatal("expected sender blamed")
	}
}
