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

package message

import (
	"context"
	"time"

	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// abortCollectStub is a Handler that is waiting for peer Err messages.
type abortCollectStub struct {
	msgType types.MessageType
	need    uint32
}

func (s *abortCollectStub) MessageType() types.MessageType { return s.msgType }
func (s *abortCollectStub) GetRequiredMessageCount() uint32 {
	return s.need
}
func (s *abortCollectStub) IsHandled(log.Logger, string) bool { return false }
func (s *abortCollectStub) HandleMessage(log.Logger, types.Message) error {
	return nil
}
func (s *abortCollectStub) Finalize(log.Logger) (types.Handler, error) { return nil, nil }
func (s *abortCollectStub) AbortCollecting() bool                      { return true }

var _ = Describe("Abort timeout", func() {
	It("returns ErrAbortTimeout while AbortCollecting", func() {
		listener := new(mocks.StateChangedListener)
		handler := &abortCollectStub{msgType: types.MessageType(50), need: 1}
		msgMain := NewMsgMain("self", 1, listener, handler, handler.msgType)
		msgMain.SetAbortTimeout(50 * time.Millisecond)

		listener.On("OnStateChanged", types.StateInit, types.StateFailed).Once()
		err := msgMain.messageLoop(context.Background())
		Expect(err).Should(Equal(ErrAbortTimeout))
		listener.AssertExpectations(GinkgoT())
	})

	It("does not apply abort timeout to normal handlers", func() {
		listener := new(mocks.StateChangedListener)
		handler := new(mocks.Handler)
		msgType := types.MessageType(10)
		msgMain := NewMsgMain("self", 1, listener, handler, msgType)
		msgMain.SetAbortTimeout(50 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		handler.On("MessageType").Return(msgType).Maybe()
		listener.On("OnStateChanged", types.StateInit, types.StateFailed).Once()
		err := msgMain.messageLoop(ctx)
		Expect(err).Should(Equal(context.DeadlineExceeded))
		listener.AssertExpectations(GinkgoT())
	})
})
