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
	"github.com/getamis/sirius/log"
)

type err1Handler struct {
	*round3Handler
	err1Msgs      map[string]*Message
	abortReason   error
}

func newErr1Handler(p *round3Handler, reason error) (*err1Handler, error) {
	eh := &err1Handler{
		round3Handler: p,
		err1Msgs:      make(map[string]*Message, p.peerNum+1),
		abortReason:   reason,
	}
	if p.err1Msg != nil {
		eh.err1Msgs[p.peerManager.SelfID()] = p.err1Msg
	}
	return eh, nil
}

func (p *err1Handler) MessageType() types.MessageType {
	return types.MessageType(Type_Err1)
}

func (p *err1Handler) GetRequiredMessageCount() uint32 {
	return p.peerNum + 1
}

func (p *err1Handler) InitialMsgCount() uint32 {
	return uint32(len(p.err1Msgs))
}

func (p *err1Handler) AbortCollecting() bool {
	return true
}

func (p *err1Handler) IsHandled(logger log.Logger, id string) bool {
	_, ok := p.err1Msgs[id]
	return ok
}

func (p *err1Handler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	p.err1Msgs[msg.GetId()] = msg
	return nil
}

func (p *err1Handler) Finalize(logger log.Logger) (types.Handler, error) {
	msgs := make([]*Message, 0, len(p.err1Msgs))
	for _, m := range p.err1Msgs {
		msgs = append(msgs, m)
	}
	blamed, err := p.ProcessErr1Msg(msgs)
	if err != nil {
		logger.Warn("Failed to process Err1 messages", "err", err)
		return nil, err
	}
	if p.onBlame != nil {
		p.onBlame(blamed)
	}
	return nil, p.abortReason
}

func (p *round3Handler) AbortMessageTypes() []types.MessageType {
	return []types.MessageType{types.MessageType(Type_Err1)}
}

func (p *round3Handler) OnAbortMessage(logger log.Logger, message types.Message) (types.Handler, error) {
	return p.onAbortErr1(logger, message)
}

func (p *round3Handler) onAbortErr1(logger log.Logger, message types.Message) (types.Handler, error) {
	if err := p.ensureErr1Built(); err != nil {
		logger.Warn("Failed to buildDeltaVerifyFailureMsg", "err", err)
		return nil, err
	}
	p.publishErr1()
	eh, err := newErr1Handler(p, ErrRemoteAbort)
	if err != nil {
		return nil, err
	}
	if err := eh.HandleMessage(logger, message); err != nil {
		return nil, err
	}
	return eh, nil
}

func (p *round3Handler) enterErr1Phase(logger log.Logger, reason error) (types.Handler, error) {
	if err := p.ensureErr1Built(); err != nil {
		logger.Warn("Failed to buildDeltaVerifyFailureMsg", "err", err)
		return nil, err
	}
	p.publishErr1()
	return newErr1Handler(p, reason)
}
