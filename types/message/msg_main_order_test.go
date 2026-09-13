package message

import (
	"context"
	"testing"
	"time"

	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	"github.com/getamis/sirius/log"
)

const (
	orderDigestType types.MessageType = 2
	orderRevealType types.MessageType = 3
)

type orderDigestHandler struct {
	next *orderRevealHandler
}

func (h *orderDigestHandler) MessageType() types.MessageType { return orderDigestType }
func (h *orderDigestHandler) GetRequiredMessageCount() uint32 { return 1 }
func (h *orderDigestHandler) IsHandled(log.Logger, string) bool { return false }
func (h *orderDigestHandler) HandleMessage(log.Logger, types.Message) error { return nil }
func (h *orderDigestHandler) Finalize(log.Logger) (types.Handler, error) {
	return h.next, nil
}
func (h *orderDigestHandler) OnDigestTimeout() {}

type orderRevealHandler struct {
	received chan types.Message
}

func (h *orderRevealHandler) MessageType() types.MessageType { return orderRevealType }
func (h *orderRevealHandler) GetRequiredMessageCount() uint32 { return 1 }
func (h *orderRevealHandler) IsHandled(log.Logger, string) bool { return false }
func (h *orderRevealHandler) HandleMessage(_ log.Logger, msg types.Message) error {
	select {
	case h.received <- msg:
	default:
	}
	return nil
}
func (h *orderRevealHandler) Finalize(log.Logger) (types.Handler, error) { return nil, nil }

// TestMsgMainBuffersRevealBeforeDigestBarrier verifies a future-round reveal can arrive
// before the digest barrier completes and is delivered once the barrier finalizes.
func TestMsgMainBuffersRevealBeforeDigestBarrier(t *testing.T) {
	revealCh := make(chan types.Message, 1)
	revealHandler := &orderRevealHandler{received: revealCh}
	digestHandler := &orderDigestHandler{next: revealHandler}

	listener := new(mocks.StateChangedListener)
	listener.On("OnStateChanged", types.StateInit, types.StateDone).Once()

	msgMain := NewMsgMain("self", 1, listener, digestHandler, orderDigestType, orderRevealType)

	revealMsg := new(mocks.Message)
	revealMsg.On("GetId").Return("peer").Maybe()
	revealMsg.On("GetMessageType").Return(orderRevealType).Maybe()
	revealMsg.On("IsValid").Return(true).Once()

	digestMsg := new(mocks.Message)
	digestMsg.On("GetId").Return("peer").Maybe()
	digestMsg.On("GetMessageType").Return(orderDigestType).Maybe()
	digestMsg.On("IsValid").Return(true).Once()

	// Reveal (type 3) arrives while still on digest handler (type 2).
	if err := msgMain.AddMessage("peer", revealMsg); err != nil {
		t.Fatalf("buffer reveal: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- msgMain.messageLoop(ctx)
	}()

	if err := msgMain.AddMessage("peer", digestMsg); err != nil {
		t.Fatalf("add digest: %v", err)
	}

	select {
	case got := <-revealCh:
		if got != revealMsg {
			t.Fatal("expected buffered reveal message")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for buffered reveal")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("message loop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Done")
	}
	listener.AssertExpectations(t)
}
