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
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/pairwise"
	"github.com/getamis/alice/types"
)

func (m *Message) IsValid() bool {
	switch m.Type {
	case Type_Round1Digest:
		return m.GetRound1Digest() != nil
	case Type_Round1:
		return m.GetRound1() != nil
	case Type_Round2Digest:
		return m.GetRound2Digest() != nil
	case Type_Round2:
		return m.GetRound2() != nil
	}
	return false
}

func (m *Message) GetMessageType() types.MessageType {
	return types.MessageType(m.Type)
}

func (m *Message) GetEchoMessage() types.Message {
	mm := &Message{
		Type: m.Type,
		Id:   m.Id,
	}
	switch m.Type {
	case Type_Round1Digest:
		src := m.GetRound1Digest()
		if src == nil {
			return nil
		}
		mm.Body = &Message_Round1Digest{
			Round1Digest: &Round1DigestMsg{
				D:         cloneEcPointMsg(src.GetD()),
				E:         cloneEcPointMsg(src.GetE()),
				ToPeer:    clonePeerDigests(src.GetToPeer()),
				TableRoot: cloneBytes(src.GetTableRoot()),
			},
		}
		return mm
	case Type_Round1, Type_Round2:
		return nil
	case Type_Round2Digest:
		src := m.GetRound2Digest()
		if src == nil {
			return nil
		}
		mm.Body = &Message_Round2Digest{
			Round2Digest: &Round2DigestMsg{
				ToPeer:    clonePeerDigests(src.GetToPeer()),
				TableRoot: cloneBytes(src.GetTableRoot()),
			},
		}
		return mm
	}
	return nil
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}

func clonePeerDigests(in []*PeerDigestEntry) []*PeerDigestEntry {
	if in == nil {
		return nil
	}
	out := make([]*PeerDigestEntry, len(in))
	for i, e := range in {
		if e == nil {
			continue
		}
		out[i] = &PeerDigestEntry{
			PeerId: e.GetPeerId(),
			Digest: cloneBytes(e.GetDigest()),
		}
	}
	return out
}

func cloneEcPointMsg(src *ecpointgrouplaw.EcPointMessage) *ecpointgrouplaw.EcPointMessage {
	if src == nil {
		return nil
	}
	return &ecpointgrouplaw.EcPointMessage{
		Curve: src.GetCurve(),
		X:     cloneBytes(src.GetX()),
		Y:     cloneBytes(src.GetY()),
	}
}

// re-export for tests
var (
	ErrPairwiseDigestMismatch = pairwise.ErrPairwiseDigestMismatch
	ErrPairwiseDigestTable    = pairwise.ErrPairwiseDigestTable
	ErrDigestBarrier          = pairwise.ErrDigestBarrier
	ErrDigestTableRoot        = pairwise.ErrDigestTableRoot
)
