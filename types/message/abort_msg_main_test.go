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
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AbortMsgMain", func() {
	var (
		abortMain       *AbortMsgMain
		mockMessageMain *mocks.MessageMain
		abortType       = types.MessageType(99)
	)

	BeforeEach(func() {
		mockMessageMain = new(mocks.MessageMain)
		abortMain = NewAbortMsgMain(mockMessageMain, abortType)
	})

	It("stops the protocol on abort messages", func() {
		mockMsg := new(mocks.Message)
		mockMsg.On("GetMessageType").Return(abortType).Once()
		mockMessageMain.On("Stop").Once()

		err := abortMain.AddMessage("peer-1", mockMsg)
		Expect(err).Should(Equal(ErrAbortReceived))
		mockMessageMain.AssertExpectations(GinkgoT())
	})
})
