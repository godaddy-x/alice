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

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/blame"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types"
)

// ProcessErr1Msg verifies Err1 broadcasts and returns a BlameContribution
// (Confirmed = cryptographic fail; Suspect = absent / global-Δ / ambiguous cohort).
func (p *round3Handler) ProcessErr1Msg(msgs []*Message) (blame.Contribution, error) {
	if err := cggmp.ValidateIAParticipantCount(len(p.peers) + 1); err != nil {
		return blame.Contribution{}, err
	}
	confirmed := make(map[string]struct{})
	suspect := make(map[string]struct{})
	errSenders := make(map[string]struct{})
	ambiguous := false
	curve := p.pubKey.GetCurve()
	curveN := curve.Params().N
	selfID := p.peerManager.SelfID()

	for _, m := range msgs {
		senderID := m.GetId()
		if senderID == selfID {
			continue
		}
		sender, ok := p.peers[senderID]
		if !ok {
			continue // ignore unknown senders (not in session)
		}
		errSenders[senderID] = struct{}{}
		if sender.round3Data == nil || sender.round1Data == nil || sender.round2Data == nil {
			confirmed[senderID] = struct{}{}
			continue
		}
		body := m.GetErr1()
		if body == nil {
			confirmed[senderID] = struct{}{}
			continue
		}

		senderN := sender.para.GetN()
		kgamma := new(big.Int).SetBytes(body.KgammaCiphertext)
		peerMsg := body.Peers[selfID]
		if body.MulProof == nil || peerMsg == nil || peerMsg.DecModQ == nil {
			confirmed[senderID] = struct{}{}
			continue
		}
		if err := body.MulProof.Verify(sender.ssidWithBk, senderN, sender.round1Data.kCiphertext, sender.round1Data.gammaCiphertext, kgamma, curveN); err != nil {
			confirmed[senderID] = struct{}{}
			continue
		}
		if !ciphertextEqBytes(peerMsg.D, sender.round1Data.D) || !ciphertextEqInt(peerMsg.F, sender.round2Data.f) {
			confirmed[senderID] = struct{}{}
			continue
		}
		if !p.sessionRound2MatchesDigest(senderID) {
			confirmed[senderID] = struct{}{}
			continue
		}
		if !peerKeysMatch(expectedErrComponentIDs(selfID, senderID, p.peers), body.Peers) {
			confirmed[senderID] = struct{}{}
			continue
		}
		components, ok := errProductComponents(body.Peers)
		if !ok {
			confirmed[senderID] = struct{}{}
			continue
		}
		nSquare := new(big.Int).Mul(senderN, senderN)
		rawC, ok := reconstructPaillierProduct(kgamma, nSquare, components)
		if !ok {
			confirmed[senderID] = struct{}{}
			continue
		}
		product, ok := parsePeerProductCiphertext(peerMsg.ProductCiphertext)
		if !ok || product.Cmp(rawC) != 0 {
			confirmed[senderID] = struct{}{}
			continue
		}
		peerNs := errPeerPaillierNs(selfID, p.paillierKey.GetN(), p.peers, body.Peers)
		if len(peerNs) != len(body.Peers) {
			confirmed[senderID] = struct{}{}
			continue
		}
		switch matchDecModQWithBetaCorrection(peerMsg.DecModQ, sender.ssidWithBk, senderN, product, sender.round3Data.delta, curveN, peerNs, p.own.para) {
		case blame.MaskNone:
			confirmed[senderID] = struct{}{}
		case blame.MaskAmbiguous:
			ambiguous = true
		case blame.MaskUnique:
			// self-consistent; no blame on sender
		}
	}

	if len(confirmed) == 0 && !ambiguous && len(msgs) > 0 {
		sumDelta := new(big.Int).Set(p.delta)
		bigDelta := p.BigDelta.Copy()
		deltaOK := true
		for id, peer := range p.peers {
			if peer.round3Data == nil {
				confirmed[id] = struct{}{}
				deltaOK = false
				continue
			}
			sumDelta.Add(sumDelta, peer.round3Data.delta)
			round3Msg := peer.GetMessage(types.MessageType(Type_Round3))
			if round3Msg == nil {
				confirmed[id] = struct{}{}
				deltaOK = false
				continue
			}
			round3 := getMessage(round3Msg).GetRound3()
			if round3 == nil {
				confirmed[id] = struct{}{}
				deltaOK = false
				continue
			}
			Delta, err := round3.BigDelta.ToPoint()
			if err != nil {
				confirmed[id] = struct{}{}
				deltaOK = false
				continue
			}
			var addErr error
			bigDelta, addErr = bigDelta.Add(Delta)
			if addErr != nil {
				deltaOK = false
				break
			}
		}
		if deltaOK {
			sumDelta.Mod(sumDelta, curveN)
			gDelta := pt.NewBase(curve).ScalarMult(sumDelta)
			if !gDelta.Equal(bigDelta) {
				// Global Δ mismatch: Suspect all Err senders (IA-03 over-blame).
				for id := range errSenders {
					suspect[id] = struct{}{}
				}
			}
		}
	}

	blameAbsentSenders(selfID, p.peers, msgs, suspect)
	return finalizeErrBlame(p.ambiguousMaskPolicy, errSenders, confirmed, suspect, ambiguous), nil
}

// ProcessErr2Msg verifies Err2 broadcasts and returns a BlameContribution.
func (p *round4Handler) ProcessErr2Msg(msgs []*Message) (blame.Contribution, error) {
	if err := cggmp.ValidateIAParticipantCount(len(p.peers) + 1); err != nil {
		return blame.Contribution{}, err
	}
	confirmed := make(map[string]struct{}, len(msgs))
	suspect := make(map[string]struct{})
	errSenders := make(map[string]struct{})
	ambiguous := false
	selfID := p.peerManager.SelfID()

	for _, m := range msgs {
		senderID := m.GetId()
		if senderID == selfID {
			continue
		}
		sender, ok := p.peers[senderID]
		if !ok {
			continue // ignore unknown senders (not in session)
		}
		errSenders[senderID] = struct{}{}
		if sender.round4Data == nil || sender.round1Data == nil || sender.round1Data.kCiphertext == nil || sender.round2Data == nil {
			confirmed[senderID] = struct{}{}
			continue
		}
		body := m.GetErr2()
		entry := (*Err2PeerMsg)(nil)
		if body != nil {
			entry = body.Peers[selfID]
		}
		if body == nil || entry == nil || p.R == nil || p.msg == nil {
			confirmed[senderID] = struct{}{}
			continue
		}

		senderN := sender.para.GetN()
		dciphertext := new(big.Int).SetBytes(body.KMulBkShareCiphertext)
		bkPartial := sender.partialPubKey.ScalarMult(sender.bkcoefficient)

		if entry.MulStarProof == nil ||
			entry.MulStarProof.Verify(parameter, sender.ssidWithBk, senderN, sender.round1Data.kCiphertext, dciphertext, p.own.para, bkPartial) != nil {
			confirmed[senderID] = struct{}{}
			continue
		}
		if entry.DecModQ == nil || entry.DecModQKm == nil ||
			!ciphertextEqBytes(entry.D, sender.round1Data.Dhat) ||
			!ciphertextEqInt(entry.F, sender.round2Data.fhat) ||
			!peerKeysMatch(expectedErrComponentIDs(selfID, senderID, p.peers), body.Peers) ||
			!p.sessionRound2MatchesDigest(senderID) {
			confirmed[senderID] = struct{}{}
			continue
		}
		components, ok := errProductComponents(body.Peers)
		nSquare := new(big.Int).Mul(senderN, senderN)
		inner, recOK := reconstructPaillierProduct(dciphertext, nSquare, components)
		if !ok || !recOK {
			confirmed[senderID] = struct{}{}
			continue
		}
		product, prodOK := parsePeerProductCiphertext(entry.ProductCiphertext)
		if !prodOK || product.Cmp(inner) != 0 {
			confirmed[senderID] = struct{}{}
			continue
		}
		chi, chiOK := parseErr2Chi(body.GetChi(), p.pubKey.GetCurve().Params().N)
		peerNs := errPeerPaillierNs(selfID, p.paillierKey.GetN(), p.peers, body.Peers)
		curveN := p.pubKey.GetCurve().Params().N
		if !chiOK || len(peerNs) != len(body.Peers) {
			confirmed[senderID] = struct{}{}
			continue
		}
		switch matchDecModQWithBetaCorrection(entry.DecModQ, sender.ssidWithBk, senderN, product, chi, curveN, peerNs, p.own.para) {
		case blame.MaskNone:
			confirmed[senderID] = struct{}{}
			continue
		case blame.MaskAmbiguous:
			ambiguous = true
		case blame.MaskUnique:
			// continue to DecModQKm
		}
		km := new(big.Int).Exp(sender.round1Data.kCiphertext, new(big.Int).SetBytes(p.msg), nSquare)
		xKm := new(big.Int).Mul(p.R.GetX(), chi)
		xKm.Sub(sender.round4Data.sigma, xKm)
		xKm.Mod(xKm, curveN)
		if err := entry.DecModQKm.VerifyModQ(parameter, sender.ssidWithBk, senderN, km, xKm, p.own.para); err != nil {
			confirmed[senderID] = struct{}{}
		}
	}

	blameAbsentSenders(selfID, p.peers, msgs, suspect)
	return finalizeErrBlame(p.ambiguousMaskPolicy, errSenders, confirmed, suspect, ambiguous), nil
}
