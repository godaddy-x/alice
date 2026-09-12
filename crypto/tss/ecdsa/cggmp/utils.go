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
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	"github.com/getamis/alice/crypto/homo/paillier"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"google.golang.org/protobuf/proto"
)

const (
	safePedModulusBits = 2048
	// minPaillierModQDistanceBits rejects N ≡ r (mod q) with |r| or |q-r| too small.
	// Prevents count-enumeration forgery when N ≡ ±1 (mod q) (Scheme A' PublicX).
	minPaillierModQDistanceBits = 128
	// MaxIARemotePeers is the max number of remote peers in one Sign session for
	// identifiable abort (Err count enumeration ≤2^8 and bounded DecModQ lift).
	// Total participants (including self) must be ≤ MaxIARemotePeers+1 (9).
	MaxIARemotePeers = 8
)

var (
	ErrInvalidDeltaString   = errors.New("invalid delta string")
	ErrSmallPedModulus      = errors.New("ped modulus too small")
	ErrUnsafePaillierModQ   = errors.New("paillier N too close to 0 mod curve order")
	ErrTooManyPeersForIA    = errors.New("too many peers for identifiable abort")
)

// ValidateIAParticipantCount enforces Scheme A′ safety bounds (≤ MaxIARemotePeers+1 total).
func ValidateIAParticipantCount(participantCount int) error {
	if participantCount <= 0 || participantCount > MaxIARemotePeers+1 {
		return ErrTooManyPeersForIA
	}
	return nil
}

func ParseBigIntString(s string, base int) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, ErrInvalidDeltaString
	}
	return v, nil
}

// ValidatePaillierNModQ rejects N mod q in {0} or within a safe distance of 0 or q
// (covers N≡±1 and other small-difference residues used to forge PublicX masks).
func ValidatePaillierNModQ(n, q *big.Int) error {
	if n == nil || q == nil || n.Sign() <= 0 || q.Sign() <= 0 {
		return ErrUnsafePaillierModQ
	}
	r := new(big.Int).Mod(n, q)
	if r.Sign() == 0 {
		return ErrUnsafePaillierModQ
	}
	qMinusR := new(big.Int).Sub(q, r)
	// Always reject ±1 mod q.
	if r.Cmp(big1) == 0 || qMinusR.Cmp(big1) == 0 {
		return ErrUnsafePaillierModQ
	}
	// For full-size curve orders, also reject residues in (0, 2^128) ∪ (q−2^128, q).
	minDist := new(big.Int).Lsh(big1, minPaillierModQDistanceBits)
	if minDist.Cmp(q) >= 0 {
		return nil
	}
	if r.Cmp(minDist) < 0 || qMinusR.Cmp(minDist) < 0 {
		return ErrUnsafePaillierModQ
	}
	return nil
}

func ValidatePed(ped *paillierzkproof.PederssenOpenParameter, curveN *big.Int) error {
	n := ped.GetN()
	if n.BitLen() < safePedModulusBits {
		return ErrSmallPedModulus
	}
	if err := paillier.ValidateNoSmallFactor(n); err != nil {
		return err
	}
	return ValidatePaillierNModQ(n, curveN)
}

func ValidateAllPed(ped map[string]*paillierzkproof.PederssenOpenParameter, curveN *big.Int) error {
	for id, p := range ped {
		if p == nil {
			return errors.New("nil ped parameter for peer " + id)
		}
		if err := ValidatePed(p, curveN); err != nil {
			return err
		}
	}
	return nil
}

func ComputeSignSSID(ssid, msg []byte) []byte {
	totalLen := 4 + len(ssid) + 4 + len(msg)
	result := make([]byte, 0, totalLen)
	appendWithLength := func(data []byte) {
		lengthBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
		result = append(result, lengthBuf...)
		result = append(result, data...)
	}

	appendWithLength(ssid)
	appendWithLength(msg)
	return result
}

func ComputeSSID(sid, id, rid []byte) []byte {
	totalLen := 4 + len(sid) + 4 + len(id) + 4 + len(rid)
	result := make([]byte, 0, totalLen)
	appendWithLength := func(data []byte) {
		lengthBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
		result = append(result, lengthBuf...)
		result = append(result, data...)
	}

	appendWithLength(sid)
	appendWithLength(id)
	appendWithLength(rid)

	return result
}

func ComputeZKSsid(ssid []byte, bk *birkhoffinterpolation.BkParameter, fieldOrder *big.Int) []byte {
	separation := []byte(",")
	result := make([]byte, len(ssid))
	copy(result, ssid)
	result = append(result, separation...)
	byteLen := (fieldOrder.BitLen() + 7) / 8
	xBytes := make([]byte, byteLen)
	bk.GetX().FillBytes(xBytes)
	return append(xBytes, result...)
}

func Broadcast(pm types.PeerManager, msg proto.Message) {
	for _, id := range pm.PeerIDs() {
		pm.MustSend(id, msg)
	}
}
