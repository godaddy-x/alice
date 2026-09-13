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

package sign

import (
	"math/big"

	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/blame"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"google.golang.org/protobuf/proto"
)

type errPeerDF interface {
	GetD() []byte
	GetF() []byte
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

func cloneEcPointMsg(m *ecpointgrouplaw.EcPointMessage) *ecpointgrouplaw.EcPointMessage {
	if m == nil {
		return nil
	}
	return proto.Clone(m).(*ecpointgrouplaw.EcPointMessage)
}

func cloneDecry(m *paillierzkproof.DecryMessage) *paillierzkproof.DecryMessage {
	if m == nil {
		return nil
	}
	return proto.Clone(m).(*paillierzkproof.DecryMessage)
}

func cloneMul(m *paillierzkproof.MulMessage) *paillierzkproof.MulMessage {
	if m == nil {
		return nil
	}
	return proto.Clone(m).(*paillierzkproof.MulMessage)
}

func cloneMulStar(m *paillierzkproof.MulStarMessage) *paillierzkproof.MulStarMessage {
	if m == nil {
		return nil
	}
	return proto.Clone(m).(*paillierzkproof.MulStarMessage)
}

func parsePeerProductCiphertext(peerProduct []byte) (*big.Int, bool) {
	if len(peerProduct) == 0 {
		return nil, false
	}
	return new(big.Int).SetBytes(peerProduct), true
}

func parseErr2Chi(chiBytes []byte, q *big.Int) (*big.Int, bool) {
	if len(chiBytes) == 0 || q == nil || q.Sign() <= 0 {
		return nil, false
	}
	chi := new(big.Int).SetBytes(chiBytes)
	if chi.Sign() < 0 || chi.Cmp(q) >= 0 {
		return nil, false
	}
	return chi, true
}

func ciphertextEqInt(got []byte, want *big.Int) bool {
	if want == nil || len(got) == 0 {
		return false
	}
	return new(big.Int).SetBytes(got).Cmp(want) == 0
}

func ciphertextEqBytes(got, want []byte) bool {
	if len(got) == 0 || len(want) == 0 {
		return false
	}
	return new(big.Int).SetBytes(got).Cmp(new(big.Int).SetBytes(want)) == 0
}

func blameAbsentSenders(selfID string, peers map[string]*peer, msgs []*Message, blamed map[string]struct{}) {
	present := make(map[string]struct{}, len(msgs))
	for _, m := range msgs {
		if m != nil {
			present[m.GetId()] = struct{}{}
		}
	}
	for id := range peers {
		if id == selfID {
			continue
		}
		if _, ok := present[id]; !ok {
			blamed[id] = struct{}{}
		}
	}
}

// finalizeErrBlame merges optional ambiguous-mask cohort and normalizes Confirmed ∩ Suspect = ∅.
func finalizeErrBlame(
	policy blame.AmbiguousMaskPolicy,
	errSenders, confirmed, suspect map[string]struct{},
	ambiguous bool,
) blame.Contribution {
	r := blame.Result{Confirmed: confirmed, Suspect: suspect}
	if ambiguous {
		r.Merge(blame.ApplyAmbiguousMask(policy, errSenders, confirmed))
	} else {
		r.Normalize()
	}
	return blame.Contribution{Confirmed: r.Confirmed, Suspect: r.Suspect}
}

func expectedErrComponentIDs(selfID, senderID string, peers map[string]*peer) map[string]struct{} {
	out := map[string]struct{}{selfID: {}}
	for id := range peers {
		if id != senderID {
			out[id] = struct{}{}
		}
	}
	return out
}

func peerKeysMatch[T any](expected map[string]struct{}, peers map[string]T) bool {
	if len(expected) != len(peers) {
		return false
	}
	for id := range expected {
		var zero T
		v, ok := peers[id]
		if !ok || any(v) == any(zero) {
			return false
		}
	}
	return true
}

func reconstructPaillierProduct(h *big.Int, nSquare *big.Int, components map[string][2]*big.Int) (*big.Int, bool) {
	if h == nil || nSquare == nil || nSquare.Sign() <= 0 {
		return nil, false
	}
	acc := new(big.Int).Set(h)
	for _, df := range components {
		d, f := df[0], df[1]
		if d == nil || f == nil {
			return nil, false
		}
		fInv := new(big.Int).ModInverse(f, nSquare)
		if fInv == nil {
			return nil, false
		}
		acc.Mul(acc, d)
		acc.Mul(acc, fInv)
		acc.Mod(acc, nSquare)
	}
	return acc, true
}

func errProductComponents[T errPeerDF](peers map[string]T) (map[string][2]*big.Int, bool) {
	if len(peers) == 0 {
		return nil, false
	}
	out := make(map[string][2]*big.Int, len(peers))
	for id, entry := range peers {
		var zero T
		if any(entry) == any(zero) {
			return nil, false
		}
		d, f := entry.GetD(), entry.GetF()
		if len(d) == 0 || len(f) == 0 {
			return nil, false
		}
		out[id] = [2]*big.Int{new(big.Int).SetBytes(d), new(big.Int).SetBytes(f)}
	}
	return out, true
}

// matchDecModQWithBetaCorrection verifies DecModQ(C, x) for count masks
// x = (share + Σ c_j N_j) mod q, c_j∈{0,1} (≤2^8). Finds the first success then
// continues scanning until a second success (MaskAmbiguous) or the end
// (MaskUnique / MaskNone). Does not early-return on the first match alone.
func matchDecModQWithBetaCorrection(
	proof *paillierzkproof.DecModQMessage,
	ssid []byte,
	senderN, C, share, q *big.Int,
	peerNs map[string]*big.Int,
	ped *paillierzkproof.PederssenOpenParameter,
) blame.MaskMatchResult {
	if proof == nil || C == nil || share == nil || q == nil || len(peerNs) == 0 {
		return blame.MaskNone
	}
	ids := make([]string, 0, len(peerNs))
	for id := range peerNs {
		ids = append(ids, id)
	}
	if len(ids) > cggmp.MaxIARemotePeers {
		return blame.MaskNone
	}
	n := len(ids)
	matches := 0
	for mask := 0; mask < (1 << n); mask++ {
		counts := make(map[string]*big.Int, n)
		for i, id := range ids {
			if mask&(1<<i) != 0 {
				counts[id] = big.NewInt(1)
			} else {
				counts[id] = big.NewInt(0)
			}
		}
		x := cggmp.DecModQPublicX(share, q, peerNs, counts)
		if err := proof.VerifyModQ(parameter, ssid, senderN, C, x, ped); err == nil {
			matches++
			if matches >= 2 {
				return blame.MaskAmbiguous
			}
		}
	}
	if matches == 0 {
		return blame.MaskNone
	}
	return blame.MaskUnique
}

func errPeerPaillierNs[T any](selfID string, ownN *big.Int, localPeers map[string]*peer, errPeers map[string]T) map[string]*big.Int {
	out := make(map[string]*big.Int, len(errPeers))
	for id := range errPeers {
		if id == selfID {
			out[id] = ownN
			continue
		}
		if peer, ok := localPeers[id]; ok && peer.para != nil {
			out[id] = peer.para.GetN()
		}
	}
	return out
}
