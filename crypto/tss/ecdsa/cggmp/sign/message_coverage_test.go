package sign

import (
	"testing"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
)

func TestMessageIsValidUnknownType(t *testing.T) {
	m := &Message{Type: 9999, Body: &Message_Round1{Round1: &Round1Msg{}}}
	if m.IsValid() {
		t.Fatal("unknown type should be invalid")
	}
}

func TestGetEchoMessageNilRound1DigestBody(t *testing.T) {
	m := &Message{Type: Type_Round1Digest, Id: "p1", Body: &Message_Round1Digest{}}
	if m.GetEchoMessage() != nil {
		t.Fatal("nil Round1Digest body should skip echo")
	}
}

func TestGetEchoMessageNilRound2DigestBody(t *testing.T) {
	m := &Message{Type: Type_Round2Digest, Id: "p1", Body: &Message_Round2Digest{}}
	if m.GetEchoMessage() != nil {
		t.Fatal("nil Round2Digest body should skip echo")
	}
}

func TestGetEchoMessageNilRound3DigestBody(t *testing.T) {
	m := &Message{Type: Type_Round3Digest, Id: "p1", Body: &Message_Round3Digest{}}
	if m.GetEchoMessage() != nil {
		t.Fatal("nil Round3Digest body should skip echo")
	}
}

func TestGetEchoMessageNilRound4Body(t *testing.T) {
	m := &Message{Type: Type_Round4, Id: "p1", Body: &Message_Round4{}}
	if m.GetEchoMessage() != nil {
		t.Fatal("nil Round4 body should skip echo")
	}
}

func TestGetEchoMessageNilErrBodies(t *testing.T) {
	if (&Message{Type: Type_Err1, Body: &Message_Err1{}}).GetEchoMessage() != nil {
		t.Fatal("nil Err1 body should skip echo")
	}
	if (&Message{Type: Type_Err2, Body: &Message_Err2{}}).GetEchoMessage() != nil {
		t.Fatal("nil Err2 body should skip echo")
	}
}

func TestGetEchoMessageUnknownType(t *testing.T) {
	m := &Message{Type: 9999, Id: "p1"}
	if m.GetEchoMessage() != nil {
		t.Fatal("unknown type should return nil echo")
	}
}

func TestClonePeerDigestsSkipsNilEntry(t *testing.T) {
	out := clonePeerDigests([]*PeerDigestEntry{
		nil,
		{PeerId: "p1", Digest: make([]byte, 32)},
	})
	if out[0] != nil {
		t.Fatal("nil entry should remain nil")
	}
	if out[1].GetPeerId() != "p1" {
		t.Fatal("expected cloned peer id")
	}
}

func TestCloneErr1PeersHandlesNilPeer(t *testing.T) {
	out := cloneErr1Peers(map[string]*Err1PeerMsg{
		"p1": nil,
		"p2": {D: []byte("d")},
	})
	if out["p1"] != nil {
		t.Fatal("nil peer should stay nil")
	}
	if string(out["p2"].GetD()) != "d" {
		t.Fatal("expected cloned D")
	}
}

func TestCloneErr2PeersHandlesNilPeer(t *testing.T) {
	out := cloneErr2Peers(map[string]*Err2PeerMsg{
		"p1": nil,
		"p2": {D: []byte("d")},
	})
	if out["p1"] != nil {
		t.Fatal("nil peer should stay nil")
	}
	if string(out["p2"].GetD()) != "d" {
		t.Fatal("expected cloned D")
	}
}

func TestCloneErr1PeersNilMap(t *testing.T) {
	if cloneErr1Peers(nil) != nil {
		t.Fatal("nil map should stay nil")
	}
}

func TestCloneErr2PeersNilMap(t *testing.T) {
	if cloneErr2Peers(nil) != nil {
		t.Fatal("nil map should stay nil")
	}
}

func TestIsValidAllMessageTypes(t *testing.T) {
	cases := []struct {
		typ  Type
		body interface{}
	}{
		{Type_Round1Digest, &Message_Round1Digest{Round1Digest: &Round1DigestMsg{}}},
		{Type_Round1, &Message_Round1{Round1: &Round1Msg{}}},
		{Type_Round2Digest, &Message_Round2Digest{Round2Digest: &Round2DigestMsg{}}},
		{Type_Round2, &Message_Round2{Round2: &Round2Msg{}}},
		{Type_Round3Digest, &Message_Round3Digest{Round3Digest: &Round3DigestMsg{}}},
		{Type_Round3, &Message_Round3{Round3: &Round3Msg{}}},
		{Type_Round4, &Message_Round4{Round4: &Round4Msg{}}},
		{Type_Err1, &Message_Err1{Err1: &Err1Msg{}}},
		{Type_Err2, &Message_Err2{Err2: &Err2Msg{}}},
	}
	for _, c := range cases {
		m := &Message{Type: c.typ}
		switch b := c.body.(type) {
		case *Message_Round1Digest:
			m.Body = b
		case *Message_Round1:
			m.Body = b
		case *Message_Round2Digest:
			m.Body = b
		case *Message_Round2:
			m.Body = b
		case *Message_Round3Digest:
			m.Body = b
		case *Message_Round3:
			m.Body = b
		case *Message_Round4:
			m.Body = b
		case *Message_Err1:
			m.Body = b
		case *Message_Err2:
			m.Body = b
		}
		if !m.IsValid() {
			t.Fatalf("type %v should be valid", c.typ)
		}
	}
}

func TestGetEchoMessageRound2DigestClonesGamma(t *testing.T) {
	srcGamma := &pt.EcPointMessage{Curve: 1, X: []byte("x"), Y: []byte("y")}
	m := &Message{
		Type: Type_Round2Digest,
		Id:   "p1",
		Body: &Message_Round2Digest{
			Round2Digest: &Round2DigestMsg{
				Gamma:     srcGamma,
				TableRoot: make([]byte, 32),
			},
		},
	}
	echo := m.GetEchoMessage().(*Message)
	srcGamma.X[0] ^= 0xff
	if echo.GetRound2Digest().GetGamma().GetX()[0] == srcGamma.X[0] {
		t.Fatal("echo should clone gamma independently")
	}
}
