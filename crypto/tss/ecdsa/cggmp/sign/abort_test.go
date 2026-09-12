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

package sign

import (
	"github.com/getamis/alice/crypto/ecpointgrouplaw"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Echo message", func() {
	It("GetEchoMessage returns non-nil for Round1", func() {
		m := &Message{
			Type: Type_Round1,
			Id:   "peer-1",
			Body: &Message_Round1{
				Round1: &Round1Msg{
					KCiphertext:     []byte("k"),
					GammaCiphertext: []byte("g"),
				},
			},
		}
		echo := m.GetEchoMessage()
		Expect(echo).NotTo(BeNil())
		Expect(echo.(*Message).GetRound1().GetKCiphertext()).To(Equal([]byte("k")))
	})

	It("GetEchoMessage returns Err1/Err2 payloads for abort echo", func() {
		err1 := &Message{
			Type: Type_Err1,
			Id:   "peer-1",
			Body: &Message_Err1{Err1: &Err1Msg{
				KgammaCiphertext: []byte("kg"),
				Peers: map[string]*Err1PeerMsg{
					"peer-2": {ProductCiphertext: []byte("c2"), D: []byte("d2"), F: []byte("f2")},
				},
			}},
		}
		echo1 := err1.GetEchoMessage()
		Expect(echo1).NotTo(BeNil())
		Expect(echo1.(*Message).GetErr1().GetKgammaCiphertext()).To(Equal([]byte("kg")))
		Expect(echo1.(*Message).GetErr1().Peers).To(HaveKey("peer-2"))
		echoPeer := echo1.(*Message).GetErr1().Peers["peer-2"]
		Expect(echoPeer.GetD()).To(Equal([]byte("d2")))
		err1.GetErr1().Peers["peer-2"].D[0] ^= 0xff
		Expect(echoPeer.GetD()).To(Equal([]byte("d2")))

		err2 := &Message{
			Type: Type_Err2,
			Id:   "peer-1",
			Body: &Message_Err2{Err2: &Err2Msg{
				KMulBkShareCiphertext: []byte("kb"),
				Chi:                   []byte("chi"),
				Peers: map[string]*Err2PeerMsg{
					"peer-2": {ProductCiphertext: []byte("c2"), D: []byte("d2"), F: []byte("f2")},
				},
			}},
		}
		echo2 := err2.GetEchoMessage()
		Expect(echo2).NotTo(BeNil())
		Expect(echo2.(*Message).GetErr2().GetKMulBkShareCiphertext()).To(Equal([]byte("kb")))
		Expect(echo2.(*Message).GetErr2().GetChi()).To(Equal([]byte("chi")))
		err2.GetErr2().Chi[0] ^= 0xff
		Expect(echo2.(*Message).GetErr2().GetChi()).To(Equal([]byte("chi")))
	})

	It("GetEchoMessage returns broadcast fields for Round2–Round4", func() {
		r2 := &Message{
			Type: Type_Round2,
			Id:   "peer-1",
			Body: &Message_Round2{
				Round2: &Round2Msg{
					Gamma: &ecpointgrouplaw.EcPointMessage{Curve: 1, X: []byte("x"), Y: []byte("y")},
				},
			},
		}
		echo2 := r2.GetEchoMessage()
		Expect(echo2).NotTo(BeNil())
		Expect(echo2.(*Message).GetRound2().GetGamma().GetX()).To(Equal([]byte("x")))

		r3 := &Message{
			Type: Type_Round3,
			Id:   "peer-1",
			Body: &Message_Round3{
				Round3: &Round3Msg{
					Delta:    "42",
					BigDelta: &ecpointgrouplaw.EcPointMessage{Curve: 1, X: []byte("dx"), Y: []byte("dy")},
				},
			},
		}
		echo3 := r3.GetEchoMessage()
		Expect(echo3).NotTo(BeNil())
		Expect(echo3.(*Message).GetRound3().GetDelta()).To(Equal("42"))

		r4 := &Message{
			Type: Type_Round4,
			Id:   "peer-1",
			Body: &Message_Round4{
				Round4: &Round4Msg{Sigmai: []byte("sig")},
			},
		}
		echo4 := r4.GetEchoMessage()
		Expect(echo4).NotTo(BeNil())
		Expect(echo4.(*Message).GetRound4().GetSigmai()).To(Equal([]byte("sig")))
	})
})
