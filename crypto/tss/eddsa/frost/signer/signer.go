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
	"math/big"
	"sync"
	"time"

	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/blame"
	"github.com/getamis/alice/crypto/tss/dkg"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
	"google.golang.org/protobuf/proto"
)

type Result struct {
	R *ecpointgrouplaw.ECPoint
	S *big.Int
}

type Signer struct {
	ph *round1DigestHandler
	ms *message.MsgMain
	types.MessageMain

	blamedMu    sync.RWMutex
	blameResult blame.Result
}

func NewSigner(pubKey *ecpointgrouplaw.ECPoint, peerManager types.PeerManager, threshold uint32, share *big.Int, dkgResult *dkg.Result, msg []byte, listener types.StateChangedListener) (*Signer, error) {
	numPeers := peerManager.NumPeers()
	if err := validateParticipantCount(int(numPeers) + 1); err != nil {
		return nil, err
	}
	peerIDs := append([]string{peerManager.SelfID()}, peerManager.PeerIDs()...)
	pubMsg, err := pubKey.ToEcPointMessage()
	if err != nil {
		return nil, err
	}
	pubBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(pubMsg)
	if err != nil {
		return nil, err
	}
	ssid := ComputeFrostSignSSID(nil, msg, pubBytes, threshold, peerIDs)
	ph, err := newRound1(pubKey, peerManager, threshold, share, dkgResult, msg, ssid)
	if err != nil {
		log.Warn("Failed to new a public key handler", "err", err)
		return nil, err
	}
	signer := &Signer{}
	ph.onBlame = signer.storeBlame
	r1d := newRound1DigestHandler(ph)
	ms := message.NewMsgMain(peerManager.SelfID(),
		numPeers,
		listener,
		r1d,
		types.MessageType(Type_Round1Digest),
		types.MessageType(Type_Round1),
		types.MessageType(Type_Round2Digest),
		types.MessageType(Type_Round2),
	)
	ms.SetAbortTimeout(2 * time.Minute)
	signer.ms = ms
	collector := cggmp.NewAbortMsgCollector[*Message]()
	signer.MessageMain = cggmp.WrapEchoAbortCollect(ms, peerManager, collector, func(m *Message) bool {
		return false
	}, func(authorID string) {
		signer.storeBlame(cggmp.BlameContributionFromConfirmed(map[string]struct{}{authorID: {}}))
	})
	signer.ph = r1d
	return signer, nil
}

func (s *Signer) storeBlame(c cggmp.BlameContribution) {
	s.blamedMu.Lock()
	defer s.blamedMu.Unlock()
	s.blameResult.Merge(c)
}

func (s *Signer) SetAbortTimeout(dur time.Duration) {
	if s.ms != nil {
		s.ms.SetAbortTimeout(dur)
	}
}

func (s *Signer) Start() {
	if err := s.ph.prepareRound1Digest(); err != nil {
		log.Warn("Failed to prepare Round1Digest", "err", err)
		if s.ms != nil {
			_ = s.ms.Fail()
		}
		return
	}
	s.MessageMain.Start()
	s.ph.broadcastRound1Digest()
}

// GetResult returns the final result: public key, share, bks (including self bk)
func (s *Signer) GetResult() (*Result, error) {
	if s.GetState() != types.StateDone {
		return nil, tss.ErrNotReady
	}

	h := s.GetHandler()
	rh, ok := h.(*round2)
	if !ok {
		log.Error("We cannot convert to result handler in done state")
		return nil, tss.ErrNotReady
	}

	return &Result{
		R: rh.r,
		S: new(big.Int).Set(rh.z),
	}, nil
}

// GetBlameResult returns Confirmed vs Suspect (StateFailed only).
func (s *Signer) GetBlameResult() (cggmp.BlameResult, error) {
	if s.GetState() != types.StateFailed {
		return cggmp.BlameResult{}, ErrBlamedPeersNotReady
	}
	s.blamedMu.RLock()
	defer s.blamedMu.RUnlock()
	out := cggmp.BlameResult{
		Confirmed: blame.CopyMap(s.blameResult.Confirmed),
		Suspect:   blame.CopyMap(s.blameResult.Suspect),
	}
	return out, nil
}

func (s *Signer) GetConfirmedPeers() (map[string]struct{}, error) {
	r, err := s.GetBlameResult()
	if err != nil {
		return nil, err
	}
	return r.Confirmed, nil
}

func (s *Signer) GetSuspectPeers() (map[string]struct{}, error) {
	r, err := s.GetBlameResult()
	if err != nil {
		return nil, err
	}
	return r.Suspect, nil
}

// GetBlamedPeers returns Confirmed ∪ Suspect (compat; deprecated for penalty logic).
func (s *Signer) GetBlamedPeers() (map[string]struct{}, error) {
	r, err := s.GetBlameResult()
	if err != nil {
		return nil, err
	}
	return r.Union(), nil
}

// GetBlamedPeer returns one blamed peer id if any (deprecated helper).
func (s *Signer) GetBlamedPeer() string {
	blamed, err := s.GetBlamedPeers()
	if err != nil || len(blamed) == 0 {
		h := s.GetHandler()
		rh, ok := h.(*round2)
		if !ok || rh.blamedPeer == "" {
			return ""
		}
		return rh.blamedPeer
	}
	for id := range blamed {
		return id
	}
	return ""
}
