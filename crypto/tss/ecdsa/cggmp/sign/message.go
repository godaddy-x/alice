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
	"github.com/getamis/alice/types"
)

func (m *Message) IsValid() bool {
	switch m.Type {
	case Type_Round1:
		return m.GetRound1() != nil
	case Type_Round2:
		return m.GetRound2() != nil
	case Type_Round3:
		return m.GetRound3() != nil
	case Type_Round4:
		return m.GetRound4() != nil
	case Type_Err1:
		return m.GetErr1() != nil
	case Type_Err2:
		return m.GetErr2() != nil
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
	case Type_Round1:
		mm.Body = &Message_Round1{
			Round1: &Round1Msg{
				KCiphertext:     m.GetRound1().GetKCiphertext(),
				GammaCiphertext: m.GetRound1().GetGammaCiphertext(),
				// Not broadcast to all in echo protocol
				// Psi:             m.GetRound1().GetPsi(),
			},
		}
		return mm
	case Type_Round2:
		src := m.GetRound2()
		if src == nil {
			return nil
		}
		// Pairwise D/F differ per recipient; Γ_i must be consistent (global broadcast component).
		mm.Body = &Message_Round2{
			Round2: &Round2Msg{
				Gamma: cloneEcPointMsg(src.GetGamma()),
			},
		}
		return mm
	case Type_Round3:
		src := m.GetRound3()
		if src == nil {
			return nil
		}
		// psidoublepai is pairwise; echo only δ and BigDelta (must match across recipients).
		mm.Body = &Message_Round3{
			Round3: &Round3Msg{
				Delta:    src.GetDelta(),
				BigDelta: cloneEcPointMsg(src.GetBigDelta()),
			},
		}
		return mm
	case Type_Round4:
		src := m.GetRound4()
		if src == nil {
			return nil
		}
		mm.Body = &Message_Round4{
			Round4: &Round4Msg{
				Sigmai: cloneBytes(src.GetSigmai()),
			},
		}
		return mm
	case Type_Err1:
		src := m.GetErr1()
		if src == nil {
			return nil
		}
		mm.Body = &Message_Err1{
			Err1: &Err1Msg{
				KgammaCiphertext: cloneBytes(src.GetKgammaCiphertext()),
				MulProof:         cloneMul(src.GetMulProof()),
				Peers:            cloneErr1Peers(src.GetPeers()),
			},
		}
		return mm
	case Type_Err2:
		src := m.GetErr2()
		if src == nil {
			return nil
		}
		mm.Body = &Message_Err2{
			Err2: &Err2Msg{
				KMulBkShareCiphertext: cloneBytes(src.GetKMulBkShareCiphertext()),
				Peers:                 cloneErr2Peers(src.GetPeers()),
				Chi:                   cloneBytes(src.GetChi()),
			},
		}
		return mm
	}
	return nil
}

func cloneErr1Peers(in map[string]*Err1PeerMsg) map[string]*Err1PeerMsg {
	if in == nil {
		return nil
	}
	out := make(map[string]*Err1PeerMsg, len(in))
	for k, v := range in {
		if v == nil {
			out[k] = nil
			continue
		}
		out[k] = &Err1PeerMsg{
			DecModQ:           cloneDecry(v.GetDecModQ()),
			ProductCiphertext: cloneBytes(v.GetProductCiphertext()),
			D:                 cloneBytes(v.GetD()),
			F:                 cloneBytes(v.GetF()),
		}
	}
	return out
}

func cloneErr2Peers(in map[string]*Err2PeerMsg) map[string]*Err2PeerMsg {
	if in == nil {
		return nil
	}
	out := make(map[string]*Err2PeerMsg, len(in))
	for k, v := range in {
		if v == nil {
			out[k] = nil
			continue
		}
		out[k] = &Err2PeerMsg{
			MulStarProof:      cloneMulStar(v.GetMulStarProof()),
			DecModQ:           cloneDecry(v.GetDecModQ()),
			ProductCiphertext: cloneBytes(v.GetProductCiphertext()),
			D:                 cloneBytes(v.GetD()),
			F:                 cloneBytes(v.GetF()),
			DecModQKm:         cloneDecry(v.GetDecModQKm()),
		}
	}
	return out
}
