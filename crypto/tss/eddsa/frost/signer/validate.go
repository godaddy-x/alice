// Copyright © 2022 AMIS Technologies
package signer

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/utils"
	"github.com/getamis/alice/types"
)

var (
	ErrNilPubKey          = errors.New("frost: nil public key")
	ErrTrivialPubKey      = errors.New("frost: trivial public key")
	ErrNilShare           = errors.New("frost: nil share")
	ErrNilPeerManager     = errors.New("frost: nil peer manager")
	ErrEmptySelfID        = errors.New("frost: empty self id")
	ErrNilDKGResult       = errors.New("frost: nil dkg result")
	ErrEmptyDKGMaps       = errors.New("frost: empty dkg Bks/Ys")
	ErrDKGMapLenMismatch  = errors.New("frost: Bks and Ys length mismatch")
	ErrDKGMissingPeer     = errors.New("frost: dkg result missing session peer")
	ErrDKGExtraPeer       = errors.New("frost: dkg result has unexpected peer")
	ErrDKGNilBkOrY        = errors.New("frost: nil Bk or Y in dkg result")
	ErrDKGCurveMismatch   = errors.New("frost: Y curve mismatches public key")
	ErrDKGTrivialPartialY = errors.New("frost: trivial partial public key")
	ErrDKGPubKeyMismatch  = errors.New("frost: dkg PublicKey mismatches signing pubKey")
	ErrSharePartialPubKey = errors.New("frost: share does not match partial public key")
	ErrShareOutOfRange    = errors.New("frost: share out of range")
)

// validateFrostDKGResult is the FR-02 entry gate: local-only checks before Sign starts.
// It does not add network rounds.
func validateFrostDKGResult(pubKey *ecpointgrouplaw.ECPoint, peerManager types.PeerManager, threshold uint32, share *big.Int, dkgResult *dkg.Result) error {
	if peerManager == nil {
		return ErrNilPeerManager
	}
	if pubKey == nil {
		return ErrNilPubKey
	}
	if pubKey.IsIdentity() {
		return ErrTrivialPubKey
	}
	if share == nil {
		return ErrNilShare
	}
	if dkgResult == nil {
		return ErrNilDKGResult
	}
	if dkgResult.Bks == nil || dkgResult.Ys == nil || len(dkgResult.Bks) == 0 || len(dkgResult.Ys) == 0 {
		return ErrEmptyDKGMaps
	}
	if len(dkgResult.Bks) != len(dkgResult.Ys) {
		return ErrDKGMapLenMismatch
	}

	selfID := peerManager.SelfID()
	if selfID == "" {
		return ErrEmptySelfID
	}
	expected := make(map[string]struct{}, peerManager.NumPeers()+1)
	expected[selfID] = struct{}{}
	for _, id := range peerManager.PeerIDs() {
		if id == "" {
			return ErrEmptySelfID
		}
		expected[id] = struct{}{}
	}
	if uint32(len(expected)) != peerManager.NumPeers()+1 {
		return fmt.Errorf("frost: duplicate peer ids in PeerManager")
	}
	if len(dkgResult.Bks) != len(expected) {
		return fmt.Errorf("%w: got %d want %d", ErrDKGExtraPeer, len(dkgResult.Bks), len(expected))
	}
	for id := range expected {
		if _, ok := dkgResult.Bks[id]; !ok {
			return fmt.Errorf("%w: %s", ErrDKGMissingPeer, id)
		}
		if _, ok := dkgResult.Ys[id]; !ok {
			return fmt.Errorf("%w: %s", ErrDKGMissingPeer, id)
		}
	}
	for id := range dkgResult.Bks {
		if _, ok := expected[id]; !ok {
			return fmt.Errorf("%w: %s", ErrDKGExtraPeer, id)
		}
	}

	curve := pubKey.GetCurve()
	if curve == nil || curve.Params() == nil || curve.Params().N == nil {
		return ErrNilPubKey
	}
	curveN := curve.Params().N
	if err := utils.InRange(share, big.NewInt(1), curveN); err != nil {
		return ErrShareOutOfRange
	}
	if dkgResult.Share != nil && dkgResult.Share.Cmp(share) != 0 {
		return ErrSharePartialPubKey
	}

	bbks := make(birkhoffinterpolation.BkParameters, 0, len(dkgResult.Bks))
	sgs := make([]*ecpointgrouplaw.ECPoint, 0, len(dkgResult.Bks))
	// Stable order not required for CheckValid/ValidatePublicKey as long as bk[i] pairs with sg[i].
	for id, bk := range dkgResult.Bks {
		if bk == nil || bk.GetX() == nil {
			return fmt.Errorf("%w: bk %s", ErrDKGNilBkOrY, id)
		}
		y := dkgResult.Ys[id]
		if y == nil {
			return fmt.Errorf("%w: y %s", ErrDKGNilBkOrY, id)
		}
		if y.IsIdentity() {
			return fmt.Errorf("%w: %s", ErrDKGTrivialPartialY, id)
		}
		if !y.IsSameCurve(pubKey) {
			return fmt.Errorf("%w: %s", ErrDKGCurveMismatch, id)
		}
		bbks = append(bbks, bk)
		sgs = append(sgs, y)
	}

	if dkgResult.PublicKey != nil {
		if dkgResult.PublicKey.IsIdentity() {
			return ErrTrivialPubKey
		}
		if !dkgResult.PublicKey.Equal(pubKey) {
			return ErrDKGPubKeyMismatch
		}
	}

	if err := bbks.CheckValid(threshold, curveN); err != nil {
		return err
	}
	if err := bbks.ValidatePublicKey(sgs, threshold, pubKey); err != nil {
		return err
	}

	shareG := ecpointgrouplaw.ScalarBaseMult(curve, share)
	if !shareG.Equal(dkgResult.Ys[selfID]) {
		return ErrSharePartialPubKey
	}
	return nil
}
