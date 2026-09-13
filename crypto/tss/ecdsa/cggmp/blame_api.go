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

package cggmp

import "github.com/getamis/alice/crypto/tss/blame"

// Thin re-exports for call sites that already import cggmp.

type (
	BlameContribution   = blame.Contribution
	BlameResult         = blame.Result
	AmbiguousMaskPolicy = blame.AmbiguousMaskPolicy
)

func BlameContributionFromConfirmed(peers map[string]struct{}) BlameContribution {
	return blame.FromConfirmed(peers)
}

func BlameContributionFromSuspect(peers map[string]struct{}) BlameContribution {
	return blame.FromSuspect(peers)
}
