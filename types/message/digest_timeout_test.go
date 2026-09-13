// Copyright © 2022 AMIS Technologies
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

type digestBarrierStub struct {
	msgType       types.MessageType
	need          uint32
	timeoutCalled bool
}

func (s *digestBarrierStub) MessageType() types.MessageType { return s.msgType }
func (s *digestBarrierStub) GetRequiredMessageCount() uint32 {
	return s.need
}
func (s *digestBarrierStub) IsHandled(log.Logger, string) bool { return false }
func (s *digestBarrierStub) HandleMessage(log.Logger, types.Message) error {
	return nil
}
func (s *digestBarrierStub) Finalize(log.Logger) (types.Handler, error) { return nil, nil }
func (s *digestBarrierStub) OnDigestTimeout()                         { s.timeoutCalled = true }

var _ = Describe("Digest barrier timeout", func() {
	It("returns ErrDigestTimeout and calls OnDigestTimeout", func() {
		listener := new(mocks.StateChangedListener)
		handler := &digestBarrierStub{msgType: types.MessageType(0), need: 1}
		msgMain := NewMsgMain("self", 1, listener, handler, handler.msgType)
		msgMain.SetAbortTimeout(50 * time.Millisecond)

		listener.On("OnStateChanged", types.StateInit, types.StateFailed).Once()
		err := msgMain.messageLoop(context.Background())
		Expect(err).Should(Equal(ErrDigestTimeout))
		Expect(handler.timeoutCalled).Should(BeTrue())
		listener.AssertExpectations(GinkgoT())
	})
})
