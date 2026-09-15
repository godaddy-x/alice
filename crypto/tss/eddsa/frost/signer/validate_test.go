// Copyright © 2022 AMIS Technologies
package signer

import (
	"errors"
	"math/big"
	"testing"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/types/mocks"
)

func frostTwoPartyFixture(t *testing.T) (
	curve elliptic.Curve,
	pub *ecpointgrouplaw.ECPoint,
	ss [][]*big.Int,
	bks map[string]*birkhoffinterpolation.BkParameter,
	ys map[string]*ecpointgrouplaw.ECPoint,
	pm0 *tss.TestPeerManager,
) {
	t.Helper()
	curve = elliptic.Ed25519()
	ss = [][]*big.Int{
		{big.NewInt(1), big.NewInt(102), big.NewInt(0)},
		{big.NewInt(2), big.NewInt(104), big.NewInt(0)},
	}
	pub = ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(100))
	bks = map[string]*birkhoffinterpolation.BkParameter{
		tss.GetTestID(0): birkhoffinterpolation.NewBkParameter(ss[0][0], 0),
		tss.GetTestID(1): birkhoffinterpolation.NewBkParameter(ss[1][0], 0),
	}
	ys = map[string]*ecpointgrouplaw.ECPoint{
		tss.GetTestID(0): ecpointgrouplaw.ScalarBaseMult(curve, ss[0][1]),
		tss.GetTestID(1): ecpointgrouplaw.ScalarBaseMult(curve, ss[1][1]),
	}
	pm0 = tss.NewTestPeerManager(0, 2)
	return curve, pub, ss, bks, ys, pm0
}

func TestValidateFrostDKGResultOK(t *testing.T) {
	_, pub, ss, bks, ys, pm0 := frostTwoPartyFixture(t)
	err := validateFrostDKGResult(pub, pm0, 2, ss[0][1], &dkg.Result{Bks: bks, Ys: ys, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewSignerRejectsBadShare(t *testing.T) {
	_, pub, _, bks, ys, pm0 := frostTwoPartyFixture(t)
	_, err := NewSigner(pub, pm0, 2, big.NewInt(1), &dkg.Result{Bks: bks, Ys: ys}, []byte("msg"), new(mocks.StateChangedListener))
	if !errors.Is(err, ErrSharePartialPubKey) {
		t.Fatalf("got %v, want ErrSharePartialPubKey", err)
	}
}

func TestNewSignerRejectsMissingPeer(t *testing.T) {
	_, pub, ss, bks, ys, pm0 := frostTwoPartyFixture(t)
	delete(bks, tss.GetTestID(1))
	delete(ys, tss.GetTestID(1))
	_, err := NewSigner(pub, pm0, 2, ss[0][1], &dkg.Result{Bks: bks, Ys: ys}, []byte("msg"), new(mocks.StateChangedListener))
	if err == nil {
		t.Fatal("expected error for missing peer")
	}
}

func TestNewSignerRejectsExtraPeer(t *testing.T) {
	_, pub, ss, bks, ys, pm0 := frostTwoPartyFixture(t)
	bks["stranger"] = birkhoffinterpolation.NewBkParameter(big.NewInt(9), 0)
	ys["stranger"] = ecpointgrouplaw.ScalarBaseMult(elliptic.Ed25519(), big.NewInt(9))
	_, err := NewSigner(pub, pm0, 2, ss[0][1], &dkg.Result{Bks: bks, Ys: ys}, []byte("msg"), new(mocks.StateChangedListener))
	if err == nil {
		t.Fatal("expected error for extra peer")
	}
}

func TestNewSignerRejectsNilDKG(t *testing.T) {
	_, pub, ss, _, _, pm0 := frostTwoPartyFixture(t)
	_, err := NewSigner(pub, pm0, 2, ss[0][1], nil, []byte("msg"), new(mocks.StateChangedListener))
	if !errors.Is(err, ErrNilDKGResult) {
		t.Fatalf("got %v, want ErrNilDKGResult", err)
	}
}

func TestNewSignerRejectsPubKeyMismatch(t *testing.T) {
	curve, pub, ss, bks, ys, pm0 := frostTwoPartyFixture(t)
	wrongPub := ecpointgrouplaw.ScalarBaseMult(curve, big.NewInt(7))
	_, err := NewSigner(pub, pm0, 2, ss[0][1], &dkg.Result{Bks: bks, Ys: ys, PublicKey: wrongPub}, []byte("msg"), new(mocks.StateChangedListener))
	if !errors.Is(err, ErrDKGPubKeyMismatch) {
		t.Fatalf("got %v, want ErrDKGPubKeyMismatch", err)
	}
}

func TestNewSignerRejectsTrivialPubKey(t *testing.T) {
	curve, _, ss, bks, ys, pm0 := frostTwoPartyFixture(t)
	id := ecpointgrouplaw.NewIdentity(curve)
	_, err := NewSigner(id, pm0, 2, ss[0][1], &dkg.Result{Bks: bks, Ys: ys}, []byte("msg"), new(mocks.StateChangedListener))
	if !errors.Is(err, ErrTrivialPubKey) {
		t.Fatalf("got %v, want ErrTrivialPubKey", err)
	}
}

func TestNewSignerRejectsShareOutOfRange(t *testing.T) {
	curve, pub, _, bks, ys, pm0 := frostTwoPartyFixture(t)
	_, err := NewSigner(pub, pm0, 2, big.NewInt(0), &dkg.Result{Bks: bks, Ys: ys}, []byte("msg"), new(mocks.StateChangedListener))
	if !errors.Is(err, ErrShareOutOfRange) {
		t.Fatalf("got %v, want ErrShareOutOfRange", err)
	}
	_, err = NewSigner(pub, pm0, 2, curve.Params().N, &dkg.Result{Bks: bks, Ys: ys}, []byte("msg"), new(mocks.StateChangedListener))
	if !errors.Is(err, ErrShareOutOfRange) {
		t.Fatalf("got %v for N, want ErrShareOutOfRange", err)
	}
}

func TestNewSignerRejectsNilPeerManager(t *testing.T) {
	_, pub, ss, bks, ys, _ := frostTwoPartyFixture(t)
	_, err := NewSigner(pub, nil, 2, ss[0][1], &dkg.Result{Bks: bks, Ys: ys}, []byte("msg"), new(mocks.StateChangedListener))
	if !errors.Is(err, ErrNilPeerManager) {
		t.Fatalf("got %v, want ErrNilPeerManager", err)
	}
}

func TestNewSignerRejectsDKGShareMismatch(t *testing.T) {
	_, pub, ss, bks, ys, pm0 := frostTwoPartyFixture(t)
	_, err := NewSigner(pub, pm0, 2, ss[0][1], &dkg.Result{
		Bks: bks, Ys: ys, Share: big.NewInt(1),
	}, []byte("msg"), new(mocks.StateChangedListener))
	if !errors.Is(err, ErrSharePartialPubKey) {
		t.Fatalf("got %v, want ErrSharePartialPubKey", err)
	}
}
