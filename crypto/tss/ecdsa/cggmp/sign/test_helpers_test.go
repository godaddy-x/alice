package sign

import (
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
)

type staticPM struct{ self string }

func (p *staticPM) NumPeers() uint32          { return 1 }
func (p *staticPM) PeerIDs() []string         { return []string{"peer"} }
func (p *staticPM) SelfID() string            { return p.self }
func (p *staticPM) MustSend(string, interface{}) {}

type threePartyPM struct{ self string }

func (p *threePartyPM) NumPeers() uint32 { return 2 }
func (p *threePartyPM) PeerIDs() []string {
	return []string{tss.GetTestID(0), tss.GetTestID(1), tss.GetTestID(2)}
}
func (p *threePartyPM) SelfID() string            { return p.self }
func (p *threePartyPM) MustSend(string, interface{}) {}

func round1DigestEchoMsg(author string, k, gamma []byte) *Message {
	return &Message{
		Id:   author,
		Type: Type_Round1Digest,
		Body: &Message_Round1Digest{
			Round1Digest: &Round1DigestMsg{
				KCiphertext:     append([]byte(nil), k...),
				GammaCiphertext: append([]byte(nil), gamma...),
				TableRoot:       []byte("root"),
				ScheduleVersion: SignScheduleVersion,
			},
		},
	}
}

func round2DigestEchoMsg(author string, gamma *pt.EcPointMessage, tableRoot []byte) *Message {
	return &Message{
		Id:   author,
		Type: Type_Round2Digest,
		Body: &Message_Round2Digest{
			Round2Digest: &Round2DigestMsg{
				Gamma:     gamma,
				TableRoot: append([]byte(nil), tableRoot...),
			},
		},
	}
}

func round3DigestEchoMsg(author, delta string, bigDelta *pt.EcPointMessage, tableRoot []byte) *Message {
	return &Message{
		Id:   author,
		Type: Type_Round3Digest,
		Body: &Message_Round3Digest{
			Round3Digest: &Round3DigestMsg{
				Delta:     delta,
				BigDelta:  bigDelta,
				TableRoot: append([]byte(nil), tableRoot...),
			},
		},
	}
}
