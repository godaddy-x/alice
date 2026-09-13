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
	"bytes"
	"errors"
	"sync"

	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
	"github.com/minio/blake2b-simd"
	"google.golang.org/protobuf/proto"
)

// Message defines the message interface
//
//go:generate go run github.com/vektra/mockery/v2 --name=EchoMessage
type EchoMessage interface {
	proto.Message
	types.Message
	// GetEchoMessage() return the message to broadcast in echo protocol
	GetEchoMessage() types.Message
}

var (
	ErrNotEchoMsg    = errors.New("not a echo message")
	ErrDifferentHash = errors.New("different hash")
)

type EchoMsgMain struct {
	types.MessageMain

	logger log.Logger
	pm     types.PeerManager
	mu     sync.Mutex
	// keep echo msgs
	// map[message type][the message id]
	echoMsgs map[types.MessageType]map[string]*echoMessage

	marshalFunc func(m proto.Message) ([]byte, error)
	// onConflict is invoked with the original message author id when echo hashes diverge.
	onConflict func(authorID string)
}

type echoMessage struct {
	hash        []byte
	count       int
	originalMsg types.Message
}

func NewEchoMsgMain(next types.MessageMain, pm types.PeerManager) *EchoMsgMain {
	msgs := make(map[types.MessageType]map[string]*echoMessage)
	return &EchoMsgMain{
		MessageMain: next,
		logger:      log.New(),
		pm:          pm,
		echoMsgs:    msgs,
		// Deterministic marshal is required when echo payloads contain map fields
		// (e.g. Err1/Err2 Peers); see protobuf encoding implications for maps.
		marshalFunc: func(m proto.Message) ([]byte, error) {
			return proto.MarshalOptions{Deterministic: true}.Marshal(m)
		},
	}
}

// SetOnConflict registers a callback for echo equivocation (ErrDifferentHash).
// authorID is the GetId() of the conflicting broadcast (digest/message author).
func (t *EchoMsgMain) SetOnConflict(fn func(authorID string)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onConflict = fn
}

// NOTE: Avoid duplicate messages from the same peer should be handled in the caller
func (t *EchoMsgMain) AddMessage(senderId string, msg types.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	eMsg, ok := msg.(EchoMessage)
	if !ok {
		return ErrNotEchoMsg
	}

	hash, err := t.echoHash(eMsg)
	if err != nil {
		return err
	}
	if hash == nil {
		return t.MessageMain.AddMessage(senderId, msg)
	}

	// Init echo messages
	msgType := msg.GetMessageType()
	echoMsg, ok := t.echoMsgs[msgType]
	if !ok {
		echoMsg = make(map[string]*echoMessage)
		t.echoMsgs[msgType] = echoMsg
	}
	msgId := msg.GetId()
	// Broadcast to other peers for the first message
	m, ok := echoMsg[msgId]
	if !ok {
		for _, id := range t.pm.PeerIDs() {
			if msgId != id {
				go t.pm.MustSend(id, eMsg.GetEchoMessage())
			}
		}
		echoMsg[msgId] = &echoMessage{
			hash: hash,
		}
		m = echoMsg[msgId]
		m.originalMsg = msg
	} else if !bytes.Equal(m.hash, hash) {
		if t.onConflict != nil {
			t.onConflict(msgId)
		}
		return ErrDifferentHash
	}

	m.count++
	if m.count == int(t.pm.NumPeers()) {
		delete(t.echoMsgs[msgType], msgId)
		return t.MessageMain.AddMessage(m.originalMsg.GetId(), m.originalMsg)
	}

	return nil
}

func (t *EchoMsgMain) Fail() error {
	if mm, ok := t.MessageMain.(*MsgMain); ok {
		return mm.Fail()
	}
	return ErrBadMsg
}

func (t *EchoMsgMain) echoHash(m EchoMessage) ([]byte, error) {
	echoMsg := m.GetEchoMessage()
	if echoMsg == nil {
		return nil, nil
	}
	bs, err := t.marshalFunc(echoMsg.(proto.Message))
	if err != nil {
		return nil, err
	}
	got := blake2b.Sum256(bs)
	return got[:], nil
}
