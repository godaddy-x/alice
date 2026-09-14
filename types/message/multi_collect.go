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
	"github.com/getamis/sirius/log"
)

// MultiCollectHandler collects secondary message types in the same MsgMain
// barrier as MessageType() (e.g. Digest Echo‖Reveal co-flight).
//
// Secondary messages are HandleMessage'd on the same handler (not OnAbortMessage).
// Finalize runs only when ReadyToFinalize() is true.
type MultiCollectHandler interface {
	types.Handler
	CollectMessageTypes() []types.MessageType
	IsCollectHandled(logger log.Logger, msgType types.MessageType, id string) bool
	ReadyToFinalize() bool
}

func isCollectType(h MultiCollectHandler, msgType types.MessageType) bool {
	for _, t := range h.CollectMessageTypes() {
		if t == msgType {
			return true
		}
	}
	return false
}
