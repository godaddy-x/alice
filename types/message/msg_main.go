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
	"sync"
	"time"

	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var (
	ErrOldMessage             = errors.New("old message")
	ErrBadMsg                 = errors.New("bad message")
	ErrInvalidStateTransition = errors.New("invalid state transition")
	ErrDupMsg                 = errors.New("duplicate message")
	ErrAbortTimeout           = errors.New("abort message collection timed out")
	ErrDigestTimeout          = errors.New("pairwise digest barrier timed out")
)

type MsgMain struct {
	logger         log.Logger
	peerNum        uint32
	msgChs         *MsgChans
	state          types.MainState
	currentHandler types.Handler
	listener       types.StateChangedListener

	lock         sync.RWMutex
	handlerLock  sync.RWMutex
	cancel       context.CancelFunc
	abortTimeout time.Duration
}

func NewMsgMain(id string, peerNum uint32, listener types.StateChangedListener, initHandler types.Handler, msgTypes ...types.MessageType) *MsgMain {
	return &MsgMain{
		logger:         log.New("self", id),
		peerNum:        peerNum,
		msgChs:         NewMsgChans(peerNum, msgTypes...),
		state:          types.StateInit,
		currentHandler: initHandler,
		listener:       listener,
	}
}

// Fail transitions the session to StateFailed without running the message loop.
func (t *MsgMain) Fail() error {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.isInFinalState() {
		return ErrInvalidStateTransition
	}
	return t.setState(types.StateFailed)
}

// SetAbortTimeout limits how long an AbortCollectHandler waits for peer Err messages.
// Zero disables the timeout (default).
func (t *MsgMain) SetAbortTimeout(d time.Duration) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.abortTimeout = d
}

func (t *MsgMain) Start() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	//nolint:errcheck
	go t.messageLoop(ctx)
	t.cancel = cancel
}

func (t *MsgMain) Stop() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.cancel == nil {
		return
	}
	t.cancel()
	t.cancel = nil
}

func (t *MsgMain) AddMessage(senderId string, msg types.Message) error {
	if senderId != msg.GetId() {
		t.logger.Debug("Different sender", "senderId", senderId, "msgId", msg.GetId())
		return ErrBadMsg
	}
	currentMsgType := t.GetHandler().MessageType()
	newMessageType := msg.GetMessageType()
	if currentMsgType > newMessageType {
		t.logger.Debug("Ignore old message", "currentMsgType", currentMsgType, "newMessageType", newMessageType)
		return ErrOldMessage
	}
	return t.msgChs.Push(msg)
}

func (t *MsgMain) GetHandler() types.Handler {
	t.handlerLock.RLock()
	defer t.handlerLock.RUnlock()

	return t.currentHandler
}

func (t *MsgMain) GetState() types.MainState {
	return t.state
}

func (t *MsgMain) messageLoop(ctx context.Context) (err error) {
	defer func() {
		panicErr := recover()

		if err == nil && panicErr == nil {
			_ = t.setState(types.StateDone)
		} else {
			_ = t.setState(types.StateFailed)
		}
		t.Stop()
	}()

	handler := t.GetHandler()
	msgType := handler.MessageType()
	msgCount := initialMsgCount(handler)
	for {
		// 1. Pop messages (including abort types when supported)
		// 2. Check if the message is handled before
		// 3. Handle the message
		// 4. Check if we collect enough messages
		// 5. If yes, finalize the handler. Otherwise, wait for the next message
		msg, err := t.popMessage(ctx, handler, msgType)
		if err != nil {
			t.logger.Warn("Failed to pop message", "err", err)
			return err
		}
		id := msg.GetId()
		logger := t.logger.New("msgType", msgType, "fromId", id)

		if msg.GetMessageType() != msgType {
			abortHandler, ok := handler.(AbortHandler)
			if !ok {
				logger.Warn("Unexpected message type")
				return ErrBadMsg
			}
			nextHandler, err := abortHandler.OnAbortMessage(logger, msg)
			if err != nil {
				logger.Warn("Failed to switch abort handler", "err", err)
				return err
			}
			t.handlerLock.Lock()
			t.currentHandler = nextHandler
			handler = t.currentHandler
			t.handlerLock.Unlock()
			newType := handler.MessageType()
			logger.Info("Change handler for abort", "oldType", msgType, "newType", newType)
			msgType = newType
			msgCount = initialMsgCount(handler)
			if msgCount >= handler.GetRequiredMessageCount() {
				nextHandler, err := handler.Finalize(logger)
				if err != nil {
					logger.Warn("Failed to finalize abort handler", "err", err)
					return err
				}
				if nextHandler == nil {
					return nil
				}
				t.handlerLock.Lock()
				t.currentHandler = nextHandler
				handler = t.currentHandler
				t.handlerLock.Unlock()
				newType = handler.MessageType()
				logger.Info("Change handler", "oldType", msgType, "newType", newType)
				msgType = newType
				msgCount = initialMsgCount(handler)
			}
			continue
		}

		if handler.IsHandled(logger, id) {
			logger.Warn("The message is handled before")
			return ErrDupMsg
		}

		err = handler.HandleMessage(logger, msg)
		if err != nil {
			logger.Warn("Failed to save message", "err", err)
			return err
		}

		msgCount++
		if msgCount < handler.GetRequiredMessageCount() {
			continue
		}

		nextHandler, err := handler.Finalize(logger)
		if err != nil {
			logger.Warn("Failed to go to next handler", "err", err)
			return err
		}
		// if nextHandler is nil, it means we got the final result
		if nextHandler == nil {
			return nil
		}
		t.handlerLock.Lock()
		t.currentHandler = nextHandler
		handler = t.currentHandler
		t.handlerLock.Unlock()
		newType := handler.MessageType()
		logger.Info("Change handler", "oldType", msgType, "newType", newType)
		msgType = newType
		msgCount = initialMsgCount(handler)
	}
}

func initialMsgCount(handler types.Handler) uint32 {
	if c, ok := handler.(InitialMsgCountHandler); ok {
		return c.InitialMsgCount()
	}
	return 0
}

func (t *MsgMain) popMessage(ctx context.Context, handler types.Handler, msgType types.MessageType) (types.Message, error) {
	popCtx := ctx
	cancel := func() {}
	abortTimed := false
	digestTimed := false
	t.lock.RLock()
	timeout := t.abortTimeout
	t.lock.RUnlock()
	if timeout > 0 {
		switch h := handler.(type) {
		case DigestBarrierHandler:
			_ = h
			popCtx, cancel = context.WithTimeout(ctx, timeout)
			digestTimed = true
		case AbortCollectHandler:
			if h.AbortCollecting() {
				popCtx, cancel = context.WithTimeout(ctx, timeout)
				abortTimed = true
			}
		}
	}
	defer cancel()

	var (
		msg types.Message
		err error
	)
	if ah, ok := handler.(AbortHandler); ok {
		msgTypes := make([]types.MessageType, 0, len(ah.AbortMessageTypes())+1)
		msgTypes = append(msgTypes, msgType)
		msgTypes = append(msgTypes, ah.AbortMessageTypes()...)
		msg, err = t.msgChs.PopAny(popCtx, msgTypes...)
	} else {
		msg, err = t.msgChs.Pop(popCtx, msgType)
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			if digestTimed {
				if dth, ok := handler.(DigestBarrierHandler); ok {
					dth.OnDigestTimeout()
				}
				return nil, ErrDigestTimeout
			}
			if abortTimed {
				return nil, ErrAbortTimeout
			}
		}
		return nil, err
	}
	return msg, nil
}

func (t *MsgMain) setState(newState types.MainState) error {
	if t.isInFinalState() {
		t.logger.Warn("Invalid state transition", "old", t.state, "new", newState)
		return ErrInvalidStateTransition
	}

	t.logger.Info("State changed", "old", t.state, "new", newState)
	oldState := t.state
	t.state = newState
	t.listener.OnStateChanged(oldState, newState)
	return nil
}

func (t *MsgMain) isInFinalState() bool {
	return t.state == types.StateFailed || t.state == types.StateDone
}
