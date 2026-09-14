// Copyright © 2022 AMIS Technologies
package message

import (
	"context"
	"testing"
	"time"

	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/gomega"
)

const (
	mcDigestType types.MessageType = 20
	mcRevealType types.MessageType = 21
)

type multiCollectStub struct {
	digests, reveals int
	need             uint32
	finalized        bool
	next             types.Handler
}

func (h *multiCollectStub) MessageType() types.MessageType             { return mcDigestType }
func (h *multiCollectStub) GetRequiredMessageCount() uint32            { return h.need }
func (h *multiCollectStub) IsHandled(log.Logger, string) bool           { return false }
func (h *multiCollectStub) CollectMessageTypes() []types.MessageType   { return []types.MessageType{mcRevealType} }
func (h *multiCollectStub) IsCollectHandled(log.Logger, types.MessageType, string) bool {
	return false
}
func (h *multiCollectStub) ReadyToFinalize() bool {
	return h.digests >= int(h.need) && h.reveals >= int(h.need)
}
func (h *multiCollectStub) HandleMessage(_ log.Logger, msg types.Message) error {
	switch msg.GetMessageType() {
	case mcDigestType:
		h.digests++
	case mcRevealType:
		h.reveals++
	}
	return nil
}
func (h *multiCollectStub) Finalize(log.Logger) (types.Handler, error) {
	h.finalized = true
	return h.next, nil
}

func TestMsgMainMultiCollectCoFlight(t *testing.T) {
	g := NewWithT(t)
	listener := new(mocks.StateChangedListener)
	listener.On("OnStateChanged", types.StateInit, types.StateDone).Once()

	stub := &multiCollectStub{need: 1, next: nil}

	msgMain := NewMsgMain("self", 1, listener, stub, mcDigestType, mcRevealType)

	reveal := new(mocks.Message)
	reveal.On("GetId").Return("peer").Maybe()
	reveal.On("GetMessageType").Return(mcRevealType).Maybe()
	reveal.On("IsValid").Return(true).Once()

	digest := new(mocks.Message)
	digest.On("GetId").Return("peer").Maybe()
	digest.On("GetMessageType").Return(mcDigestType).Maybe()
	digest.On("IsValid").Return(true).Once()

	// Reveal arrives before digest (early co-flight).
	g.Expect(msgMain.AddMessage("peer", reveal)).To(Succeed())
	g.Expect(msgMain.AddMessage("peer", digest)).To(Succeed())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	g.Expect(msgMain.messageLoop(ctx)).To(Succeed())
	g.Expect(stub.finalized).To(BeTrue())
	g.Expect(stub.digests).To(Equal(1))
	g.Expect(stub.reveals).To(Equal(1))
	listener.AssertExpectations(t)
}
