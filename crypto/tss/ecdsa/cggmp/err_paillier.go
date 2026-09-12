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

package cggmp

import (
	"errors"
	"math/big"
)

var (
	ErrCannotLiftPlaintext = errors.New("cannot lift paillier plaintext onto mod q")
)

// MaxDecModQLiftK bounds k in LiftDecryptToModQBounded: Y=Decrypt(C)+k·N, |Y|<(MaxDecModQLiftK+1)·N.
//
// This is NOT the theoretical CRT span (8N/q can be ~2^1795 for secp256k1); it is an
// engineering cap tied to MaxIARemotePeers=8 MtA sessions:
//   - k≥-2: negative Paillier plaintext representatives after β correction
//   - k≤7: at most one wrap per remote peer when Σα crosses q (count_j∈{0,1})
// Raising MaxIARemotePeers without re-deriving this bound can break honest IA completeness.
const MaxDecModQLiftK = 7

// LiftDecryptToModQBounded returns Y=yEnc+k·N with k∈[-2, MaxDecModQLiftK]
// such that Y≡x (mod q).
func LiftDecryptToModQBounded(yEnc, n, x, q *big.Int) (*big.Int, error) {
	if yEnc == nil || n == nil || x == nil || q == nil || n.Sign() <= 0 || q.Sign() <= 0 {
		return nil, ErrCannotLiftPlaintext
	}
	for k := int64(-2); k <= MaxDecModQLiftK; k++ {
		y := new(big.Int).Add(yEnc, new(big.Int).Mul(big.NewInt(k), n))
		if new(big.Int).Mod(y, q).Cmp(x) == 0 {
			return y, nil
		}
	}
	return nil, ErrCannotLiftPlaintext
}

// BetaCorrectionSum returns Σ count_j·N_j (public computeBeta correction).
func BetaCorrectionSum(peerNs map[string]*big.Int, counts map[string]*big.Int) *big.Int {
	sum := new(big.Int)
	for id, n := range peerNs {
		c := counts[id]
		if c == nil || c.Sign() == 0 || n == nil {
			continue
		}
		sum.Add(sum, new(big.Int).Mul(c, n))
	}
	return sum
}

// DecModQPublicX returns (share + Σ count_j·N_j) mod q — the DecModQ challenge
// representative for untranslated product C0 (Scheme A').
func DecModQPublicX(share, q *big.Int, peerNs, counts map[string]*big.Int) *big.Int {
	x := new(big.Int).Add(share, BetaCorrectionSum(peerNs, counts))
	return x.Mod(x, q)
}

// DeriveProductEncSalt returns rho such that Enc(plaintextY, salt) equals ciphertext.
func DeriveProductEncSalt(n, nSquare, nthRoot, plaintextY, ciphertext *big.Int) *big.Int {
	salt := new(big.Int).Exp(new(big.Int).Add(n, big1), new(big.Int).Neg(plaintextY), nSquare)
	salt.Mul(salt, ciphertext)
	salt.Exp(salt, nthRoot, nSquare)
	return salt
}
