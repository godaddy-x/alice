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
	"sync"

	"github.com/getamis/alice/crypto/tss/blame"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
)

// AbortMsgCollector stores Err broadcasts for offline GetBlamedPeers fallback.
type AbortMsgCollector[T types.Message] struct {
	mu   sync.Mutex
	msgs []T
}

func NewAbortMsgCollector[T types.Message]() *AbortMsgCollector[T] {
	return &AbortMsgCollector[T]{}
}

func (c *AbortMsgCollector[T]) Record(msg T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, msg)
}

func (c *AbortMsgCollector[T]) Snapshot() []T {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]T, len(c.msgs))
	copy(out, c.msgs)
	return out
}

type errCollectMain[T types.Message] struct {
	types.MessageMain
	collector *AbortMsgCollector[T]
	isErr     func(T) bool
}

func (a *errCollectMain[T]) AddMessage(senderId string, msg types.Message) error {
	if concrete, ok := msg.(T); ok && a.isErr(concrete) {
		a.collector.Record(concrete)
	}
	return a.MessageMain.AddMessage(senderId, msg)
}

func (a *errCollectMain[T]) Fail() error {
	type failer interface {
		Fail() error
	}
	if f, ok := a.MessageMain.(failer); ok {
		return f.Fail()
	}
	return message.ErrBadMsg
}

// WrapEchoAbortCollect wraps MsgMain with Echo then Err recording.
// onEchoConflict, if non-nil, is called with the message author id on echo equivocation.
func WrapEchoAbortCollect[T types.Message](
	ms *message.MsgMain,
	pm types.PeerManager,
	collector *AbortMsgCollector[T],
	isErr func(T) bool,
	onEchoConflict func(authorID string),
) types.MessageMain {
	echoMain := message.NewEchoMsgMain(ms, pm)
	if onEchoConflict != nil {
		echoMain.SetOnConflict(onEchoConflict)
	}
	return &errCollectMain[T]{
		MessageMain: echoMain,
		collector:   collector,
		isErr:       isErr,
	}
}

// CopyBlamedMap returns a shallow copy of blamed peer ids.
func CopyBlamedMap(in map[string]struct{}) map[string]struct{} {
	return blame.CopyMap(in)
}
