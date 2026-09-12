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
	"math/big"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CGGMP Utils Suite")
}

var _ = Describe("ComputeSignSSID", func() {
	It("binds message digest into session id", func() {
		ssid := []byte("session")
		msg := []byte("digest")
		got := ComputeSignSSID(ssid, msg)
		Expect(got).NotTo(Equal(ssid))
		Expect(ComputeSignSSID(ssid, msg)).To(Equal(got))
		Expect(ComputeSignSSID(ssid, []byte("other"))).NotTo(Equal(got))
	})
})

var _ = Describe("LiftDecryptToModQBounded", func() {
	It("accepts Y=yEnc (k=0)", func() {
		n := big.NewInt(35)
		q := big.NewInt(11)
		yEnc := big.NewInt(4)
		x := big.NewInt(4)
		y, err := LiftDecryptToModQBounded(yEnc, n, x, q)
		Expect(err).Should(BeNil())
		Expect(y.Cmp(yEnc)).To(BeZero())
	})

	It("accepts k=-1 when yEnc-N ≡ x mod q", func() {
		n := big.NewInt(35)
		q := big.NewInt(11)
		yEnc := big.NewInt(4)
		// 4-35 = -31 ≡ 2 (mod 11)
		x := big.NewInt(2)
		y, err := LiftDecryptToModQBounded(yEnc, n, x, q)
		Expect(err).Should(BeNil())
		Expect(y.Cmp(big.NewInt(-31))).To(BeZero())
	})

	It("rejects residues that need |k|>7", func() {
		n := big.NewInt(35)
		q := big.NewInt(11)
		yEnc := big.NewInt(4)
		// k∈[-2,7] reaches only a few residues; 1 may or may not — pick unreachable via CRT-scale need
		// With n=35,q=11: try x that needs k=8: 4+8*35=284, 284 mod 11 = 284-25*11=284-275=9
		_, err := LiftDecryptToModQBounded(yEnc, n, big.NewInt(9), q)
		// 4+7*35=249 ≡ 249-22*11=249-242=7; 4+6*35=214≡214-19*11=214-209=5; ...
		// k=8 would give 9 but is out of range — if 9 reachable by other k, adjust.
		// Check: k=-2 → 4-70=-66 ≡ 0; -1→2; 0→4; 1→6; 2→8; 3→10; 4→1; 5→3; 6→5; 7→7.
		// Residue 9 is NOT in the set. Good.
		Expect(err).Should(Equal(ErrCannotLiftPlaintext))
	})

	It("rejects N too close to 0 mod q", func() {
		q := big.NewInt(11)
		// N ≡ 1 (mod q)
		n := big.NewInt(23) // 23 mod 11 = 1
		Expect(ValidatePaillierNModQ(n, q)).Should(Equal(ErrUnsafePaillierModQ))
		// N ≡ 0
		Expect(ValidatePaillierNModQ(big.NewInt(22), q)).Should(Equal(ErrUnsafePaillierModQ))
	})

	It("accepts typical N far from 0 mod q", func() {
		q := new(big.Int).Set(parameter.Curve.Params().N)
		// Use a synthetic N ≡ 2^200 (mod q) — well above 2^128 threshold in tests with tiny q we skip;
		// for secp q, build N = q*2 + (1<<200)
		r := new(big.Int).Lsh(big1, 200)
		n := new(big.Int).Add(new(big.Int).Mul(q, big2), r)
		Expect(ValidatePaillierNModQ(n, q)).Should(BeNil())
	})
})

var _ = Describe("DecModQPublicX", func() {
	It("adds Σ c·N before mod q", func() {
		q := big.NewInt(11)
		share := big.NewInt(3)
		peerNs := map[string]*big.Int{"p": big.NewInt(35)}
		counts := map[string]*big.Int{"p": big.NewInt(1)}
		// (3+35) mod 11 = 5
		Expect(DecModQPublicX(share, q, peerNs, counts).Cmp(big.NewInt(5))).To(BeZero())
	})
})

var _ = Describe("ValidateIAParticipantCount", func() {
	It("accepts up to 9 participants", func() {
		Expect(ValidateIAParticipantCount(9)).To(Succeed())
		Expect(ValidateIAParticipantCount(10)).NotTo(Succeed())
	})
})
