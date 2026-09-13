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
	"sync"
	"time"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
)

type Sign struct {
	ph  *round1Handler
	r1d *round1DigestHandler
	ms  *message.MsgMain
	types.MessageMain

	abortCollector *cggmp.AbortMsgCollector[*Message]

	blamedMu    sync.RWMutex
	blamedPeers map[string]struct{}
}

type Result struct {
	R *big.Int
	S *big.Int
}

func NewSign(threshold uint32, ssid []byte, share *big.Int, pubKey *pt.ECPoint, partialPubKey map[string]*pt.ECPoint, paillierKey *paillier.Paillier, ped map[string]*paillierzkproof.PederssenOpenParameter, bks map[string]*birkhoffinterpolation.BkParameter, msg []byte, peerManager types.PeerManager, listener types.StateChangedListener) (*Sign, error) {
	peerNum := peerManager.NumPeers()
	ssid = cggmp.ComputeSignSSID(ssid, msg)
	ph, err := newRound1Handler(threshold, ssid, share, pubKey, partialPubKey, paillierKey, ped, bks, msg, peerManager)
	if err != nil {
		return nil, err
	}
	collector := cggmp.NewAbortMsgCollector[*Message]()
	ph.onAbortMsg = collector.Record
	r1d := newRound1DigestHandler(ph)
	sign := &Sign{
		ph:             ph,
		abortCollector: collector,
	}
	ph.onBlamedPeers = sign.storeBlamedPeers
	ms := message.NewMsgMain(peerManager.SelfID(), peerNum, listener, r1d,
		types.MessageType(Type_Round1Digest),
		types.MessageType(Type_Round1),
		types.MessageType(Type_Round2Digest),
		types.MessageType(Type_Round2),
		types.MessageType(Type_Round3Digest),
		types.MessageType(Type_Round3),
		types.MessageType(Type_Round4),
		types.MessageType(Type_Err1),
		types.MessageType(Type_Err2),
	)
	ms.SetAbortTimeout(2 * time.Minute)
	sign.ms = ms
	sign.MessageMain = cggmp.WrapEchoAbortCollect(ms, peerManager, collector, func(m *Message) bool {
		return m.Type == Type_Err1 || m.Type == Type_Err2
	}, func(authorID string) {
		sign.storeBlamedPeers(map[string]struct{}{authorID: {}})
	})
	sign.r1d = r1d
	return sign, nil
}

func (d *Sign) storeBlamedPeers(peers map[string]struct{}) {
	d.blamedMu.Lock()
	defer d.blamedMu.Unlock()
	if d.blamedPeers == nil {
		d.blamedPeers = cggmp.CopyBlamedMap(peers)
		return
	}
	for id := range peers {
		d.blamedPeers[id] = struct{}{}
	}
}

// SetAbortTimeout configures digest-barrier and abort-collection timeouts on the inner MsgMain.
func (d *Sign) SetAbortTimeout(dur time.Duration) {
	if d.ms != nil {
		d.ms.SetAbortTimeout(dur)
	}
}

// GetBlamedPeers returns peers identified during the in-protocol abort phase.
// Only valid after StateFailed. Falls back to offline analysis of collected Err messages when needed.
func (d *Sign) GetBlamedPeers() (map[string]struct{}, error) {
	if d.GetState() != types.StateFailed {
		return nil, ErrBlamedPeersNotReady
	}
	d.blamedMu.RLock()
	if d.blamedPeers != nil {
		out := cggmp.CopyBlamedMap(d.blamedPeers)
		d.blamedMu.RUnlock()
		return out, nil
	}
	d.blamedMu.RUnlock()

	msgs := d.abortCollector.Snapshot()
	if len(msgs) == 0 {
		return map[string]struct{}{}, nil
	}
	h := d.GetHandler()
	switch rh := h.(type) {
	case *err1Handler:
		return rh.ProcessErr1Msg(msgs)
	case *err2Handler:
		return rh.ProcessErr2Msg(msgs)
	case *round3Handler:
		return rh.ProcessErr1Msg(msgs)
	case *round4Handler:
		return rh.ProcessErr2Msg(msgs)
	}
	return map[string]struct{}{}, nil
}

// GetResult returns the final result: public key, share, bks (including self bk)
func (d *Sign) GetResult() (*Result, error) {
	if d.GetState() != types.StateDone {
		return nil, tss.ErrNotReady
	}

	h := d.GetHandler()
	rh, ok := h.(*round4Handler)
	if !ok {
		log.Error("We cannot convert to result handler in done state")
		return nil, tss.ErrNotReady
	}

	return rh.result, nil
}

func (d *Sign) Start() {
	if err := d.r1d.prepareRound1Digest(); err != nil {
		log.Warn("Failed to prepare Round1Digest", "err", err)
		if d.ms != nil {
			_ = d.ms.Fail()
		}
		return
	}
	d.MessageMain.Start()
	d.r1d.broadcastRound1Digest()
}
