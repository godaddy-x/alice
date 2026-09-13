package sign

import (
	"testing"
	"time"

	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/alice/types/mocks"
	"github.com/stretchr/testify/mock"
)

func allSignMessageTypes() []types.MessageType {
	return []types.MessageType{
		types.MessageType(Type_Round1Digest),
		types.MessageType(Type_Round1),
		types.MessageType(Type_Round2Digest),
		types.MessageType(Type_Round2),
		types.MessageType(Type_Round3Digest),
		types.MessageType(Type_Round3),
		types.MessageType(Type_Round4),
		types.MessageType(Type_Err1),
		types.MessageType(Type_Err2),
	}
}

func newSignMsgMain(self string, peerNum uint32, listener types.StateChangedListener, handler types.Handler) *message.MsgMain {
	msgTypes := allSignMessageTypes()
	args := make([]types.MessageType, 0, len(msgTypes)+1)
	args = append(args, handler.MessageType())
	args = append(args, msgTypes...)
	return message.NewMsgMain(self, peerNum, listener, handler, args...)
}

func waitForState(t *testing.T, ms types.MessageMain, want types.MainState, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ms.GetState() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for state %v, got %v", want, ms.GetState())
}

func TestMsgMainRound3OnAbortErr1ViaPopAny(t *testing.T) {
	p3, p2Err := setupRound3PairForErr1Testing(t)
	if err := p2Err.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	id1 := tss.GetTestID(0)
	id2 := tss.GetTestID(1)
	remote := &Message{Id: id2, Type: Type_Err1, Body: p2Err.err1Msg.Body}

	listener := new(mocks.StateChangedListener)
	listener.On("OnStateChanged", types.StateInit, types.StateFailed).Return().Once()

	ms := newSignMsgMain(id1, 1, listener, p3)
	ms.Start()
	time.Sleep(20 * time.Millisecond)
	if err := ms.AddMessage(id2, remote); err != nil {
		t.Fatal(err)
	}
	waitForState(t, ms, types.StateFailed, 5*time.Second)
	if _, ok := ms.GetHandler().(*err1Handler); !ok {
		t.Fatalf("expected err1Handler, got %T", ms.GetHandler())
	}
	ms.Stop()
	listener.AssertExpectations(t)
}

func TestMsgMainRound4OnAbortErr2ViaPopAny(t *testing.T) {
	p4, p2Err := setupRound4PairForErr2Testing(t)
	if err := p2Err.buildSigmaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	id1 := tss.GetTestID(0)
	id2 := tss.GetTestID(1)
	remote := &Message{Id: id2, Type: Type_Err2, Body: p2Err.err2Msg.Body}

	listener := new(mocks.StateChangedListener)
	listener.On("OnStateChanged", types.StateInit, types.StateFailed).Return().Once()

	ms := newSignMsgMain(id1, 1, listener, p4)
	ms.Start()
	time.Sleep(20 * time.Millisecond)
	if err := ms.AddMessage(id2, remote); err != nil {
		t.Fatal(err)
	}
	waitForState(t, ms, types.StateFailed, 5*time.Second)
	if _, ok := ms.GetHandler().(*err2Handler); !ok {
		t.Fatalf("expected err2Handler, got %T", ms.GetHandler())
	}
	ms.Stop()
	listener.AssertExpectations(t)
}

func TestWrapEchoAbortCollectRecordsErr1(t *testing.T) {
	p3, p2Err := setupRound3PairForErr1Testing(t)
	if err := p2Err.buildDeltaVerifyFailureMsg(); err != nil {
		t.Fatal(err)
	}
	id1 := tss.GetTestID(0)
	id2 := tss.GetTestID(1)
	remote := &Message{Id: id2, Type: Type_Err1, Body: p2Err.err1Msg.Body}

	collector := cggmp.NewAbortMsgCollector[*Message]()
	listener := new(mocks.StateChangedListener)
	listener.On("OnStateChanged", mock.Anything, mock.Anything).Return().Maybe()

	pm := tss.NewTestPeerManager(0, 2)
	pm.Set(nil)
	ms := newSignMsgMain(id1, 1, listener, p3)
	wrapped := cggmp.WrapEchoAbortCollect(ms, pm, collector, func(m *Message) bool {
		return m.Type == Type_Err1 || m.Type == Type_Err2
	}, nil)

	listener.On("OnStateChanged", types.StateInit, types.StateFailed).Return().Once()

	wrapped.Start()
	time.Sleep(20 * time.Millisecond)
	if err := wrapped.AddMessage(id2, remote); err != nil {
		t.Fatal(err)
	}
	waitForState(t, wrapped, types.StateFailed, 5*time.Second)
	snap := collector.Snapshot()
	if len(snap) != 1 || snap[0].GetId() != id2 {
		t.Fatalf("expected one collected err1, got %v", snap)
	}
	wrapped.Stop()
}
