// Copyright © 2022 AMIS Technologies
//
package sign

import (
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
	case Type_Round3Digest:
		return m.GetRound3Digest() != nil
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
	case Type_Round1Digest:
		src := m.GetRound1Digest()
		if src == nil {
			return nil
		}
		mm.Body = &Message_Round1Digest{
			Round1Digest: &Round1DigestMsg{
				KCiphertext:     cloneBytes(src.GetKCiphertext()),
				GammaCiphertext: cloneBytes(src.GetGammaCiphertext()),
				ToPeer:          clonePeerDigests(src.GetToPeer()),
				TableRoot:       cloneBytes(src.GetTableRoot()),
			},
		}
		return mm
	case Type_Round1:
		// K/Γ already echoed via Round1Digest; pairwise psi is digest-gated.
		// Returning nil skips EchoMsgMain so reveal is delivered directly.
		return nil
	case Type_Round2Digest:
		src := m.GetRound2Digest()
		if src == nil {
			return nil
		}
		mm.Body = &Message_Round2Digest{
			Round2Digest: &Round2DigestMsg{
				Gamma:     cloneEcPointMsg(src.GetGamma()),
				ToPeer:    clonePeerDigests(src.GetToPeer()),
				TableRoot: cloneBytes(src.GetTableRoot()),
			},
		}
		return mm
	case Type_Round2:
		// Pairwise reveal — Gamma already in Round2Digest; skip per-message Echo.
		return nil
	case Type_Round3Digest:
		src := m.GetRound3Digest()
		if src == nil {
			return nil
		}
		mm.Body = &Message_Round3Digest{
			Round3Digest: &Round3DigestMsg{
				Delta:     src.GetDelta(),
				BigDelta:  cloneEcPointMsg(src.GetBigDelta()),
				ToPeer:    clonePeerDigests(src.GetToPeer()),
				TableRoot: cloneBytes(src.GetTableRoot()),
			},
		}
		return mm
	case Type_Round3:
		// Pairwise reveal — δ/Δ already in Round3Digest; skip per-message Echo.
		return nil
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
