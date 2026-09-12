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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("DecModQ", func() {
	var (
		cfg  *CurveConfig
		x    *big.Int
		rho  *big.Int
		Cenc *big.Int
	)

	BeforeEach(func() {
		cfg = NewS256()
		x = big.NewInt(3)
		rho = big.NewInt(5)
		Cenc = new(big.Int).Exp(new(big.Int).Add(big1, n0), x, n0Square)
		Cenc.Mul(Cenc, new(big.Int).Exp(rho, n0, n0Square))
		Cenc.Mod(Cenc, n0Square)
	})

	It("proves when Y equals x (short plaintext)", func() {
		proof, err := NewDecModQMessage(cfg, ssIDInfo, x, rho, n0, Cenc, x, ped)
		Expect(err).Should(BeNil())
		Expect(proof.VerifyModQ(cfg, ssIDInfo, n0, Cenc, x, ped)).Should(Succeed())
	})

	It("proves when Y = x + k·q is large (core IA case)", func() {
		q := cfg.Curve.Params().N
		// Keep Y < N0 (honest Paillier plaintext size) but still ≫ 2^{L+ε}.
		k := new(big.Int).Div(new(big.Int).Sub(n0, x), q)
		k.Sub(k, big1)
		Expect(k.Sign()).Should(BeNumerically(">", 0))
		Y := new(big.Int).Add(x, new(big.Int).Mul(k, q))
		Expect(Y.Cmp(n0)).Should(BeNumerically("<", 0))
		Expect(Y.BitLen()).Should(BeNumerically(">", int(cfg.LAddEpsilon)))

		Cbig := new(big.Int).Exp(new(big.Int).Add(big1, n0), Y, n0Square)
		Cbig.Mul(Cbig, new(big.Int).Exp(rho, n0, n0Square))
		Cbig.Mod(Cbig, n0Square)

		proof, err := NewDecModQMessage(cfg, ssIDInfo, Y, rho, n0, Cbig, x, ped)
		Expect(err).Should(BeNil())
		Expect(proof.VerifyModQ(cfg, ssIDInfo, n0, Cbig, x, ped)).Should(Succeed())
	})

	It("rejects CRT-scale Y = yEnc + k·N with |Y|≥8N (Scheme A')", func() {
		q := cfg.Curve.Params().N
		yEnc := new(big.Int).Add(x, big1)
		nInv := new(big.Int).ModInverse(n0, q)
		Expect(nInv).NotTo(BeNil())
		k := new(big.Int).Sub(x, yEnc)
		k.Mul(k, nInv)
		k.Mod(k, q)
		Expect(k.Sign()).Should(BeNumerically(">", 0))
		Y := new(big.Int).Add(yEnc, new(big.Int).Mul(n0, k))
		Expect(Y.Cmp(new(big.Int).Mul(n0, big.NewInt(8)))).Should(BeNumerically(">=", 0))

		Cbig := new(big.Int).Exp(new(big.Int).Add(big1, n0), yEnc, n0Square)
		Cbig.Mul(Cbig, new(big.Int).Exp(rho, n0, n0Square))
		Cbig.Mod(Cbig, n0Square)

		_, err := NewDecModQMessage(cfg, ssIDInfo, Y, rho, n0, Cbig, x, ped)
		Expect(err).ShouldNot(BeNil())
	})

	It("proves bounded lift Y = yEnc - N (k=-1)", func() {
		q := cfg.Curve.Params().N
		// yEnc ≡ x + (N mod q) (mod q) ⇒ yEnc - N ≡ x (mod q)
		nModQ := new(big.Int).Mod(n0, q)
		yEnc := new(big.Int).Add(x, nModQ)
		yEnc.Mod(yEnc, q)
		// ensure yEnc ∈ (0, N); tiny representative is fine
		if yEnc.Sign() == 0 {
			yEnc = new(big.Int).Set(q)
		}
		Expect(yEnc.Cmp(n0)).Should(BeNumerically("<", 0))
		Y := new(big.Int).Sub(yEnc, n0)
		Expect(new(big.Int).Mod(Y, q).Cmp(x)).To(BeZero())

		Cbig := new(big.Int).Exp(new(big.Int).Add(big1, n0), yEnc, n0Square)
		Cbig.Mul(Cbig, new(big.Int).Exp(rho, n0, n0Square))
		Cbig.Mod(Cbig, n0Square)

		proof, err := NewDecModQMessage(cfg, ssIDInfo, Y, rho, n0, Cbig, x, ped)
		Expect(err).Should(BeNil())
		Expect(proof.VerifyModQ(cfg, ssIDInfo, n0, Cbig, x, ped)).Should(Succeed())
	})

	It("rejects Y not congruent to x mod q at prove time", func() {
		Y := big.NewInt(4)
		Cbad := new(big.Int).Exp(new(big.Int).Add(big1, n0), Y, n0Square)
		Cbad.Mul(Cbad, new(big.Int).Exp(rho, n0, n0Square))
		Cbad.Mod(Cbad, n0Square)
		_, err := NewDecModQMessage(cfg, ssIDInfo, Y, rho, n0, Cbad, x, ped)
		Expect(err).ShouldNot(BeNil())
	})

	It("rejects tampered ciphertext", func() {
		Y := new(big.Int).Add(x, new(big.Int).Mul(big.NewInt(1000), cfg.Curve.Params().N))
		Cbig := new(big.Int).Exp(new(big.Int).Add(big1, n0), Y, n0Square)
		Cbig.Mul(Cbig, new(big.Int).Exp(rho, n0, n0Square))
		Cbig.Mod(Cbig, n0Square)
		proof, err := NewDecModQMessage(cfg, ssIDInfo, Y, rho, n0, Cbig, x, ped)
		Expect(err).Should(BeNil())

		tampered := new(big.Int).Add(Cbig, big1)
		Expect(proof.VerifyModQ(cfg, ssIDInfo, n0, tampered, x, ped)).ShouldNot(Succeed())
	})

	Context("Fiat-Shamir statement binding (PR1 gate)", func() {
		It("Tamper_Ci_In_Hash: proof for C_i must not verify under C_i'", func() {
			proof, err := NewDecModQMessage(cfg, ssIDInfo, x, rho, n0, Cenc, x, ped)
			Expect(err).Should(BeNil())

			// Alternate ciphertext encrypting a different plaintext mod q.
			otherX := new(big.Int).Add(x, big1)
			if otherX.Cmp(cfg.Curve.Params().N) >= 0 {
				otherX.Sub(otherX, cfg.Curve.Params().N)
			}
			Cother := new(big.Int).Exp(new(big.Int).Add(big1, n0), otherX, n0Square)
			Cother.Mul(Cother, new(big.Int).Exp(rho, n0, n0Square))
			Cother.Mod(Cother, n0Square)

			Expect(proof.VerifyModQ(cfg, ssIDInfo, n0, Cother, x, ped)).ShouldNot(Succeed())
		})

		It("Tamper_x_In_Hash: proof for x must not verify under x'", func() {
			proof, err := NewDecModQMessage(cfg, ssIDInfo, x, rho, n0, Cenc, x, ped)
			Expect(err).Should(BeNil())

			xPrime := new(big.Int).Add(x, big1)
			if xPrime.Cmp(cfg.Curve.Params().N) >= 0 {
				xPrime.Sub(xPrime, cfg.Curve.Params().N)
			}
			Expect(xPrime.Cmp(x)).ShouldNot(BeZero())
			Expect(proof.VerifyModQ(cfg, ssIDInfo, n0, Cenc, xPrime, ped)).ShouldNot(Succeed())
		})
	})

	It("rejects wrong public x", func() {
		proof, err := NewDecModQMessage(cfg, ssIDInfo, x, rho, n0, Cenc, x, ped)
		Expect(err).Should(BeNil())
		Expect(proof.VerifyModQ(cfg, ssIDInfo, n0, Cenc, big.NewInt(4), ped)).ShouldNot(Succeed())
	})

	It("rejects x outside [0,q)", func() {
		_, err := NewDecModQMessage(cfg, ssIDInfo, x, rho, n0, Cenc, cfg.Curve.Params().N, ped)
		Expect(err).ShouldNot(BeNil())
	})

	It("rejects oversized z1 before Exp", func() {
		proof, err := NewDecModQMessage(cfg, ssIDInfo, x, rho, n0, Cenc, x, ped)
		Expect(err).Should(BeNil())
		proof.Z1 = new(big.Int).Lsh(big1, 20000).String()
		Expect(proof.VerifyModQ(cfg, ssIDInfo, n0, Cenc, x, ped)).ShouldNot(Succeed())

		huge := make([]byte, maxDecModQZ1DecimalLen+1)
		for i := range huge {
			huge[i] = '9'
		}
		proof.Z1 = string(huge)
		Expect(proof.VerifyModQ(cfg, ssIDInfo, n0, Cenc, x, ped)).ShouldNot(Succeed())
	})
})
