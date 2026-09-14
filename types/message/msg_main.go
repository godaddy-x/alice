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
		// Finalize only when the barrier is satisfied:
		// - MultiCollect: ReadyToFinalize()
		// - otherwise: msgCount > 0 && msgCount >= required (msgCount may come from InitialMsgCount)
		if done, nextHandler, ferr := t.maybeFinalize(handler, msgType, &msgCount); ferr != nil {
			return ferr
		} else if done {
			return nil
		} else if nextHandler != nil {
			handler, msgType, msgCount = t.switchHandler(nextHandler, msgType)
			continue
		}

		msg, err := t.popMessage(ctx, handler, msgType)
		if err != nil {
			t.logger.Warn("Failed to pop message", "err", err)
			return err
		}
		id := msg.GetId()
		gotType := msg.GetMessageType()
		logger := t.logger.New("msgType", gotType, "fromId", id)

		if gotType != msgType {
			if mch, ok := handler.(MultiCollectHandler); ok && isCollectType(mch, gotType) {
				if mch.IsCollectHandled(logger, gotType, id) {
					logger.Warn("The collect message is handled before")
					return ErrDupMsg
				}
				if err := handler.HandleMessage(logger, msg); err != nil {
					logger.Warn("Failed to save collect message", "err", err)
					return err
				}
				continue
			}

			abortHandler, ok := handler.(AbortHandler)
			if !ok {
				logger.Warn("Unexpected message type")
				return ErrBadMsg
			}
			// N/A INV: abort switch, not CoFlight Next
			nextHandler, err := abortHandler.OnAbortMessage(logger, msg)
			if err != nil {
				logger.Warn("Failed to switch abort handler", "err", err)
				return err
			}
			handler, msgType, msgCount = t.switchHandler(nextHandler, msgType)
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
	}
}

func (t *MsgMain) switchHandler(next types.Handler, oldType types.MessageType) (types.Handler, types.MessageType, uint32) {
	t.handlerLock.Lock()
	t.currentHandler = next
	handler := t.currentHandler
	t.handlerLock.Unlock()
	newType := handler.MessageType()
	t.logger.Info("Change handler", "oldType", oldType, "newType", newType)
	return handler, newType, initialMsgCount(handler)
}

// maybeFinalize runs Finalize when the current barrier is complete.
// done=true means protocol finished (nil next). nextHandler set means switched.
func (t *MsgMain) maybeFinalize(handler types.Handler, msgType types.MessageType, msgCount *uint32) (bool, types.Handler, error) {
	logger := t.logger.New("msgType", msgType)
	if mch, ok := handler.(MultiCollectHandler); ok {
		if !mch.ReadyToFinalize() {
			return false, nil, nil
		}
	} else if *msgCount == 0 || *msgCount < handler.GetRequiredMessageCount() {
		return false, nil, nil
	}

	nextHandler, err := handler.Finalize(logger)
	if err != nil {
		logger.Warn("Failed to go to next handler", "err", err)
		return false, nil, err
	}
	if nextHandler == nil {
		return true, nil, nil
	}
	return false, nextHandler, nil
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
	extra := make([]types.MessageType, 0, 4)
	if mch, ok := handler.(MultiCollectHandler); ok {
		extra = append(extra, mch.CollectMessageTypes()...)
	}
	if ah, ok := handler.(AbortHandler); ok {
		extra = append(extra, ah.AbortMessageTypes()...)
	}
	if len(extra) > 0 {
		msgTypes := make([]types.MessageType, 0, len(extra)+1)
		msgTypes = append(msgTypes, msgType)
		msgTypes = append(msgTypes, extra...)
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
