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

// AbortHandler is implemented by protocol handlers that can switch into an
// identifiable-abort phase when Err messages arrive out of band.
type AbortHandler interface {
	types.Handler
	AbortMessageTypes() []types.MessageType
	OnAbortMessage(logger log.Logger, msg types.Message) (types.Handler, error)
}

// InitialMsgCountHandler reports messages already collected when a handler is entered.
type InitialMsgCountHandler interface {
	InitialMsgCount() uint32
}

// AbortCollectHandler marks handlers that are collecting Err broadcasts.
// MsgMain applies abortTimeout only while this interface is present.
type AbortCollectHandler interface {
	AbortCollecting() bool
}
