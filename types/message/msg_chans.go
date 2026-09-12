// Copyright © 2020 AMIS Technologies
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

package message

import (
	"context"
	"errors"
	"reflect"

	"github.com/getamis/alice/types"
)

var (
	// ErrInvalidMessage is return if the message is invalid
	ErrInvalidMessage = errors.New("invalid message")
	// ErrUndefinedMessage is return if the message is not defined
	ErrUndefinedMessage = errors.New("undefined message")
	// ErrFullChannel is returned if the message channel is full
	ErrFullChannel = errors.New("full channel")
)

type MsgChans struct {
	chs map[types.MessageType]chan types.Message
}

func NewMsgChans(bufferLen uint32, ts ...types.MessageType) *MsgChans {
	chs := make(map[types.MessageType]chan types.Message, len(ts))
	for _, t := range ts {
		chs[t] = make(chan types.Message, bufferLen)
	}
	return &MsgChans{
		chs: chs,
	}
}

func (m *MsgChans) Push(msg types.Message) error {
	ch, ok := m.chs[msg.GetMessageType()]
	if !ok {
		return ErrUndefinedMessage
	}
	if !msg.IsValid() {
		return ErrInvalidMessage
	}
	select {
	case ch <- msg:
		return nil
	default:
		return ErrFullChannel
	}
}

func (m *MsgChans) Pop(ctx context.Context, t types.MessageType) (types.Message, error) {
	return m.PopAny(ctx, t)
}

func (m *MsgChans) PopAny(ctx context.Context, ts ...types.MessageType) (types.Message, error) {
	if len(ts) == 0 {
		return nil, ErrUndefinedMessage
	}
	if len(ts) == 1 {
		ch, ok := m.chs[ts[0]]
		if !ok {
			return nil, ErrUndefinedMessage
		}
		select {
		case msg := <-ch:
			return msg, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	cases := make([]reflect.SelectCase, len(ts)+1)
	for i, t := range ts {
		ch, ok := m.chs[t]
		if !ok {
			return nil, ErrUndefinedMessage
		}
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
	}
	cases[len(ts)] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ctx.Done())}

	chosen, recv, recvOK := reflect.Select(cases)
	if chosen == len(ts) {
		return nil, ctx.Err()
	}
	if !recvOK {
		return nil, ctx.Err()
	}
	return recv.Interface().(types.Message), nil
}
