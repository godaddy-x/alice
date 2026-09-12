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

package paillier

import (
	"math/big"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/utils"
	"github.com/golang/protobuf/proto"
)

const (
	// DecModQZKDST distinguishes Π^{dec-mod-q} from legacy Special Decry (Figure 30).
	DecModQZKDST = "AMIS-Alice-Paillier-Decryption-ModQ-ZK-v1.0-"
	// maxDecModQZ1DecimalLen rejects oversized z1 strings before SetString/Exp (DoS).
	maxDecModQZ1DecimalLen = 8192
	decModQZ1SlackBits     = 64
	// maxDecModQYOverN = MaxDecModQLiftK+1: prover/verifier enforce |Y| < maxDecModQYOverN·N.
	// Must stay in sync with cggmp.MaxDecModQLiftK (see err_paillier.go for derivation).
	maxDecModQYOverN = 8
)

// DecModQMessage proves Decrypt(C) ≡ x (mod q) for C = Enc(Y, rho).
// Y may be large (Paillier-sized); x must be the short on-wire representative (δ or σ).
// Wire layout reuses DecryMessage; Fiat–Shamir DST differs from SpecialDecryZKDST.
type DecModQMessage = DecryMessage

// NewDecModQMessage creates a proof that C encrypts some Y with Y ≡ x (mod curve order).
// Unlike NewDecryMessage, VerifyModQ does not require |α+eY| ≤ 2^{L+ε}, so honest MtA
// product plaintexts are admissible. The EC check (ScalarMult reduces mod q) binds Y ≡ x (mod q).
func NewDecModQMessage(config *CurveConfig, ssidInfo []byte, Y, rho, N0, C, x *big.Int, ped *PederssenOpenParameter) (*DecModQMessage, error) {
	curveN := config.Curve.Params().N
	if err := utils.InRange(x, big0, curveN); err != nil {
		return nil, ErrInvalidInput
	}
	if new(big.Int).Mod(Y, curveN).Cmp(x) != 0 {
		return nil, ErrInvalidInput
	}
	if new(big.Int).Abs(new(big.Int).Set(Y)).Cmp(new(big.Int).Mul(N0, big.NewInt(maxDecModQYOverN))) >= 0 {
		return nil, ErrInvalidInput
	}
	if err := utils.InRange(C, big0, new(big.Int).Mul(N0, N0)); err != nil {
		return nil, err
	}
	if N0.Cmp(big0) <= 0 {
		return nil, ErrInvalidInput
	}

	G := pt.NewBase(config.Curve)
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()
	if pedN.Cmp(big0) <= 0 {
		return nil, ErrInvalidInput
	}

	alpha, err := utils.RandomAbsoluteRangeInt(config.TwoExpLAddepsilon)
	if err != nil {
		return nil, err
	}
	twoLAddEpsilonMulPedN := new(big.Int).Mul(config.TwoExpLAddepsilon, pedN)
	twoLMulPedN := new(big.Int).Mul(config.TwoExpL, pedN)
	mu, err := utils.RandomAbsoluteRangeInt(twoLMulPedN)
	if err != nil {
		return nil, err
	}
	v, err := utils.RandomAbsoluteRangeInt(twoLAddEpsilonMulPedN)
	if err != nil {
		return nil, err
	}
	r, err := utils.RandomCoprimeInt(N0)
	if err != nil {
		return nil, err
	}

	N0Square := new(big.Int).Mul(N0, N0)

	// S = s^Y * t^μ mod N̂
	S := new(big.Int).Mul(new(big.Int).Exp(peds, Y, pedN), new(big.Int).Exp(pedt, mu, pedN))
	S.Mod(S, pedN)
	// T = s^α * t^ν
	T := new(big.Int).Mul(new(big.Int).Exp(peds, alpha, pedN), new(big.Int).Exp(pedt, v, pedN))
	T.Mod(T, pedN)
	// A = (1+N_0)^α · r^{N_0} mod N_0^2
	A := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, N0), alpha, N0Square), new(big.Int).Exp(r, N0, N0Square))
	A.Mod(A, N0Square)

	CPoint := G.ScalarMult(alpha)
	msgCPoint, err := CPoint.ToEcPointMessage()
	if err != nil {
		return nil, err
	}

	// Fiat–Shamir: e = Hash(DST, ssid, …, C, x, …). C and x MUST stay in this
	// transcript; omitting either allows existential forgery (reuse proof with
	// substituted productCiphertext or δ/σ representative).
	// GetE samples e ∈ [-q/2,q/2] (not necessarily prime). Special-soundness
	// extraction needs e≠e'; library-wide assumption: q prime ⇒ invertible mod q;
	// gcd(e−e′,N)=1 holds except with negligible probability for RSA moduli (R1-FS).
	msgs := decModQChallengeInputs(ssidInfo, pedN.Bytes(), peds.Bytes(), pedt.Bytes(), A.Bytes(), S.Bytes(), T.Bytes(), N0.Bytes(), C.Bytes(), x.Bytes(), curveN, msgCPoint)
	e, counter, err := GetE(DecModQZKDST, curveN, msgs...)
	if err != nil {
		return nil, err
	}

	// z1 = α + e·Y as an UNREDUCED integer. Do NOT z1.Mod(q) before wire/Paillier:
	// EC ScalarMult reduces mod q internally; Paillier/Pedersen Exp must see the
	// same absolute z1 (Modulo Gap — see docs/review-v1/CGGMP.md §5.2).
	z1 := new(big.Int).Add(alpha, new(big.Int).Mul(e, Y))
	z2 := new(big.Int).Add(v, new(big.Int).Mul(e, mu))
	W := new(big.Int).Mul(r, new(big.Int).Exp(rho, e, N0))
	W.Mod(W, N0)

	return &DecryMessage{
		Counter: counter,
		S:       S.Bytes(),
		T:       T.Bytes(),
		A:       A.Bytes(),
		CPoint:  msgCPoint,
		Z1:      z1.String(),
		Z2:      z2.String(),
		W:       W.Bytes(),
	}, nil
}

// VerifyModQ checks Decrypt(C) ≡ x (mod q) for some Y with |Y|<maxDecModQYOverN·N.
//
// Soundness-critical: |z1| ≤ maxDecModQZ1 MUST be checked. Without it a cheating
// prover can take Y_mal = Y + K·N·q with |Y_mal| ≫ 8N, set z1 = α + e·Y_mal, and
// still pass EC/Paillier equations — breaking |Y|<8N and Scheme A′ accountability.
// The bound also limits Exp DoS; honest lifts use Y=Decrypt(C)+kN, k∈[-2,7].
func (msg *DecModQMessage) VerifyModQ(config *CurveConfig, ssidInfo []byte, N0, C, x *big.Int, ped *PederssenOpenParameter) error {
	G := pt.NewBase(config.Curve)
	fieldOrder := config.Curve.Params().N
	N0Square := new(big.Int).Mul(N0, N0)
	pedN := ped.GetN()
	peds := ped.GetS()
	pedt := ped.GetT()

	if err := utils.InRange(x, big0, fieldOrder); err != nil {
		return err
	}
	if err := utils.InRange(C, big0, N0Square); err != nil {
		return err
	}
	if !utils.IsRelativePrime(C, N0) {
		return ErrVerifyFailure
	}

	msgs := decModQChallengeInputs(ssidInfo, pedN.Bytes(), peds.Bytes(), pedt.Bytes(), msg.A, msg.S, msg.T, N0.Bytes(), C.Bytes(), x.Bytes(), fieldOrder, msg.CPoint)
	e, expectedCounter, err := GetE(DecModQZKDST, fieldOrder, msgs...)
	if err != nil {
		return err
	}
	if expectedCounter != msg.Counter {
		return ErrVerifyFailure
	}

	S := new(big.Int).SetBytes(msg.S)
	if err := utils.InRange(S, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(S, pedN) {
		return ErrVerifyFailure
	}

	T := new(big.Int).SetBytes(msg.T)
	if err := utils.InRange(T, big0, pedN); err != nil {
		return err
	}
	if !utils.IsRelativePrime(T, pedN) {
		return ErrVerifyFailure
	}

	A := new(big.Int).SetBytes(msg.A)
	if err := utils.InRange(A, big0, N0Square); err != nil {
		return err
	}
	if !utils.IsRelativePrime(A, N0Square) {
		return ErrVerifyFailure
	}

	if len(msg.Z1) == 0 || len(msg.Z1) > maxDecModQZ1DecimalLen {
		return ErrInvalidInput
	}
	z1, ok := new(big.Int).SetString(msg.Z1, 10)
	if !ok {
		return ErrInvalidInput
	}
	// Forces |Y|<8N for committed α (see maxDecModQZ1). Do not remove.
	if new(big.Int).Abs(new(big.Int).Set(z1)).Cmp(maxDecModQZ1(config, N0)) > 0 {
		return ErrVerifyFailure
	}
	z2, ok := new(big.Int).SetString(msg.Z2, 10)
	if !ok {
		return ErrInvalidInput
	}

	W := new(big.Int).SetBytes(msg.W)
	if err := utils.InRange(W, big0, N0); err != nil {
		return err
	}
	if !utils.IsRelativePrime(W, N0) {
		return ErrVerifyFailure
	}

	// z2 still comes from short μ; keep its range check.
	upperBdZ2 := new(big.Int).Mul(new(big.Int).Lsh(big1, uint(config.LAddEpsilon)), pedN)
	if new(big.Int).Abs(z2).Cmp(upperBdZ2) > 0 {
		return ErrVerifyFailure
	}

	// z1·G == C_point + e·(x·G). ScalarMult reduces z1 mod q internally; the
	// same unreduced z1 is used below in Paillier/Pedersen (Modulo Gap safe).
	CPoint, err := msg.CPoint.ToPoint()
	if err != nil {
		return err
	}
	comparePoint, err := CPoint.Add(G.ScalarMult(x).ScalarMult(e))
	if err != nil {
		return err
	}
	if !G.ScalarMult(z1).Equal(comparePoint) {
		return ErrVerifyFailure
	}

	// (1+N_0)^{z1} · W^{N_0} = A · C^e mod N_0^2 — z1 unreduced (not mod q).
	ACexpe := new(big.Int).Mul(A, new(big.Int).Exp(C, e, N0Square))
	ACexpe.Mod(ACexpe, N0Square)
	temp := new(big.Int).Add(big1, N0)
	temp.Exp(temp, z1, N0Square)
	compare := new(big.Int).Exp(W, N0, N0Square)
	compare.Mul(compare, temp)
	compare.Mod(compare, N0Square)
	if compare.Cmp(ACexpe) != 0 {
		return ErrVerifyFailure
	}

	// s^{z1} t^{z2} = T · S^e mod N̂
	sz1tz2 := new(big.Int).Mul(new(big.Int).Exp(peds, z1, pedN), new(big.Int).Exp(pedt, z2, pedN))
	sz1tz2.Mod(sz1tz2, pedN)
	TSexpe := new(big.Int).Mul(T, new(big.Int).Exp(S, e, pedN))
	TSexpe.Mod(TSexpe, pedN)
	if sz1tz2.Cmp(TSexpe) != 0 {
		return ErrVerifyFailure
	}

	return nil
}

// decModQChallengeInputs builds the Fiat–Shamir transcript shared by Prove and Verify.
// Public statement (C, x) is hashed here so proofs cannot be replayed under another
// productCiphertext or δ/σ representative.
func decModQChallengeInputs(ssidInfo, pedN, peds, pedt, A, S, T, N0, C, x []byte, curveN *big.Int, cPoint proto.Message) []proto.Message {
	return append(utils.GetAnyMsg(ssidInfo, pedN, peds, pedt, A, S, T, N0, C, x, curveN.Bytes()), cPoint)
}

// maxDecModQZ1 ≈ 2^{L+ε} + (8N−1)(q−1) + 2^{slack}: honest |α+eY| under |Y|<8N.
// Verifier rejects larger |z1|, which is what makes |Y|<8N soundness-enforced.
func maxDecModQZ1(config *CurveConfig, N0 *big.Int) *big.Int {
	fieldOrder := config.Curve.Params().N
	maxY := new(big.Int).Mul(N0, big.NewInt(maxDecModQYOverN))
	maxEY := new(big.Int).Mul(new(big.Int).Sub(maxY, big1), new(big.Int).Sub(fieldOrder, big1))
	maxAbs := new(big.Int).Lsh(big1, uint(config.LAddEpsilon))
	maxAbs.Add(maxAbs, maxEY)
	maxAbs.Add(maxAbs, new(big.Int).Lsh(big1, decModQZ1SlackBits))
	return maxAbs
}
