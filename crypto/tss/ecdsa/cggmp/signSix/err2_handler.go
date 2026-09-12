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

package signSix

import (
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

type err2Handler struct {
	*round6Handler
	err2Msgs    map[string]*Message
	abortReason error
}

func newErr2Handler(p *round6Handler, reason error) (*err2Handler, error) {
	eh := &err2Handler{
		round6Handler: p,
		err2Msgs:      make(map[string]*Message, p.peerNum+1),
		abortReason:   reason,
	}
	if p.roundErr2Msg != nil {
		eh.err2Msgs[p.peerManager.SelfID()] = p.roundErr2Msg
	}
	return eh, nil
}

func (p *err2Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Err2)
}

func (p *err2Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum + 1
}

func (p *err2Handler) InitialMsgCount() uint32 {
	return uint32(len(p.err2Msgs))
}

func (p *err2Handler) AbortCollecting() bool {
	return true
}

func (p *err2Handler) IsHandled(logger log.Logger, id string) bool {
	_, ok := p.err2Msgs[id]
	return ok
}

func (p *err2Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	p.err2Msgs[msg.GetId()] = msg
	return nil
}

func (p *err2Handler) Finalize(logger log.Logger) (types.Handler, error) {
	msgs := make([]*Message, 0, len(p.err2Msgs))
	for _, m := range p.err2Msgs {
		msgs = append(msgs, m)
	}
	blamed, err := p.ProcessErr2Msg(msgs)
	if err != nil {
		logger.Warn("Failed to process Err2 messages", "err", err)
		return nil, err
	}
	if p.onBlamedPeers != nil {
		p.onBlamedPeers(blamed)
	}
	return nil, p.abortReason
}

func (p *round6Handler) AbortMessageTypes() []types.MessageType {
	return []types.MessageType{
		types.MessageType(Type_Err1),
		types.MessageType(Type_Err2),
	}
}

func (p *round6Handler) OnAbortMessage(logger log.Logger, message types.Message) (types.Handler, error) {
	msg := getMessage(message)
	switch msg.Type {
	case Type_Err1:
		return p.round5Handler.onAbortErr1(logger, message)
	case Type_Err2:
		return p.onAbortErr2(logger, message)
	default:
		return nil, ErrRemoteAbort
	}
}

func (p *round6Handler) onAbortErr2(logger log.Logger, message types.Message) (types.Handler, error) {
	if p.roundErr2Msg == nil {
		if err := p.buildErr2Msg(); err != nil {
			logger.Warn("Failed to buildErr2Msg", "err", err)
			return nil, err
		}
		if p.roundErr2Msg != nil {
			if p.onAbortMsg != nil {
				p.onAbortMsg(p.roundErr2Msg)
			}
			cggmp.Broadcast(p.peerManager, p.roundErr2Msg)
		}
	}
	eh, err := newErr2Handler(p, ErrRemoteAbort)
	if err != nil {
		return nil, err
	}
	if err := eh.HandleMessage(logger, message); err != nil {
		return nil, err
	}
	return eh, nil
}

func (p *round6Handler) enterErr2Phase(logger log.Logger, reason error) (types.Handler, error) {
	if err := p.buildErr2Msg(); err != nil {
		logger.Warn("Failed to buildErr2Msg", "err", err)
		return nil, err
	}
	if p.roundErr2Msg != nil {
		if p.onAbortMsg != nil {
			p.onAbortMsg(p.roundErr2Msg)
		}
		cggmp.Broadcast(p.peerManager, p.roundErr2Msg)
	}
	return newErr2Handler(p, reason)
}
