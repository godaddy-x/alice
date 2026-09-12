// Copyright © 2022 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signer

import (
	"crypto/sha256"
	"math/big"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/utils"
	"github.com/decred/dcrd/dcrec/edwards"
)

var (
	big2 = big.NewInt(2)
)

func verifySignature(pubKey, R *ecpointgrouplaw.ECPoint, message []byte, s *big.Int) bool {
	curveType := pubKey.GetCurve()
	switch curveType {
	case elliptic.Secp256k1():
		curveP := curveType.Params().P
		curveN := curveType.Params().N
		px, py, err := liftX(pubKey.GetX(), curveType)
		if err != nil {
			return false
		}
		r := new(big.Int).Set(R.GetX())
		if r.Cmp(curveP) >= 0 {
			return false
		}
		sigS := new(big.Int).Set(s)
		if sigS.Cmp(curveN) >= 0 {
			return false
		}
		toHash := utils.Bytes32(r)
		toHash = append(toHash, utils.Bytes32(px)...)
		toHash = append(toHash, message...)
		e := new(big.Int).SetBytes(hashSignatureTag("BIPSchnorr", toHash))
		e.Mod(e, curveN)
		recoverPubKey, err := ecpointgrouplaw.NewECPoint(curveType, px, py)
		if err != nil {
			return false
		}
		r1 := ecpointgrouplaw.ScalarBaseMult(curveType, sigS)
		r2 := recoverPubKey.ScalarMult(e)
		r2 = r2.Neg()
		compareR, err := r1.Add(r2)
		if err != nil {
			return false
		}
		if compareR.IsIdentity() || !compareR.IsEvenY() || compareR.GetX().Cmp(r) != 0 {
			return false
		}
		return true

	case elliptic.Ed25519():
		edwardPubKey := edwards.NewPublicKey(edwards.Edwards(), pubKey.GetX(), pubKey.GetY())
		encodedR, err := ecpointEncoding(R)
		if err != nil {
			return false
		}
		r := new(big.Int).SetBytes(utils.ReverseByte(encodedR[:]))
		return edwards.Verify(edwardPubKey, message, r, s)
	}
	return false
}

func liftX(x *big.Int, curve elliptic.Curve) (*big.Int, *big.Int, error) {
	curveP := curve.Params().P
	if x.Cmp(big0) == -1 || x.Cmp(curveP) == 1 {
		return nil, nil, ErrNotSupportCurve
	}
	compare := new(big.Int)
	compare.Exp(x, big.NewInt(3), curveP)
	compare.Add(compare, big.NewInt(7))
	compare.Mod(compare, curveP)
	exp := new(big.Int)
	exp.Add(curveP, big1)
	exp.Div(exp, big.NewInt(4))
	y := new(big.Int)
	y.Exp(compare, exp, curveP)
	ySquare := new(big.Int)
	ySquare.Exp(y, big2, curveP)
	if compare.Cmp(ySquare) != 0 {
		return nil, nil, ErrNotSupportCurve
	}
	if new(big.Int).And(y, big1).Cmp(big1) == 0 {
		y = y.Sub(curve.Params().P, y)
	}
	return x, y, nil
}

func hashSignatureTag(tag string, x []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	toHash := tagHash[:]
	toHash = append(toHash, tagHash[:]...)
	toHash = append(toHash, x...)
	hashed := sha256.Sum256(toHash)
	return utils.Pad(hashed[:], 32)
}
