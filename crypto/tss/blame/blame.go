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

// Package blame defines Identifiable-Abort peer classification shared by
// CGGMP sign and FROST sign. Confirmed is cryptographic blame; Suspect is an
// operational hint. GetBlamedPeers-style APIs return Confirmed ∪ Suspect for
// compatibility; penalty logic must use Confirmed only.
package blame

// Result is the accumulated blame snapshot after StateFailed.
type Result struct {
	Confirmed map[string]struct{}
	Suspect   map[string]struct{}
}

// Contribution is one blame event from a call site (may carry both sets).
type Contribution struct {
	Confirmed map[string]struct{}
	Suspect   map[string]struct{}
}

// AmbiguousMaskPolicy controls IA-01 multi-mask DecModQ match handling.
type AmbiguousMaskPolicy int

const (
	// SuspectAllErr (production default): Confirmed empty for the ambiguous
	// case; Suspect = (Err senders this round) − Confirmed.
	SuspectAllErr AmbiguousMaskPolicy = iota
	// SuspectNone: neither Confirmed nor Suspect for the ambiguous cohort;
	// requires human ops intervention.
	SuspectNone
	// ConfirmAllErr: puts the cohort into Confirmed. Production builds remap
	// this to SuspectAllErr unless built with -tags alice_ia_debug.
	ConfirmAllErr
)

// MaskMatchResult is the outcome of enumerating PublicX count masks.
type MaskMatchResult int

const (
	MaskNone MaskMatchResult = iota
	MaskUnique
	MaskAmbiguous
)

// FromConfirmed builds a contribution with only Confirmed peers.
func FromConfirmed(peers map[string]struct{}) Contribution {
	return Contribution{Confirmed: CopyMap(peers)}
}

// FromSuspect builds a contribution with only Suspect peers.
func FromSuspect(peers map[string]struct{}) Contribution {
	return Contribution{Suspect: CopyMap(peers)}
}

// Union returns Confirmed ∪ Suspect (for deprecated GetBlamedPeers).
func (c Contribution) Union() map[string]struct{} {
	return UnionMaps(c.Confirmed, c.Suspect)
}

// ToResult converts a contribution into a Result (copies + normalize).
func (c Contribution) ToResult() Result {
	r := Result{
		Confirmed: CopyMap(c.Confirmed),
		Suspect:   CopyMap(c.Suspect),
	}
	r.Normalize()
	return r
}

// Normalize enforces Confirmed ∩ Suspect = ∅ (Confirmed wins).
func (r *Result) Normalize() {
	if r.Confirmed == nil {
		r.Confirmed = map[string]struct{}{}
	}
	if r.Suspect == nil {
		r.Suspect = map[string]struct{}{}
	}
	for id := range r.Confirmed {
		delete(r.Suspect, id)
	}
}

// Union returns Confirmed ∪ Suspect.
func (r Result) Union() map[string]struct{} {
	return UnionMaps(r.Confirmed, r.Suspect)
}

// Disjoint reports whether Confirmed ∩ Suspect is empty.
func (r Result) Disjoint() bool {
	for id := range r.Confirmed {
		if _, ok := r.Suspect[id]; ok {
			return false
		}
	}
	return true
}

// Merge adds c into the accumulator, then Normalizes.
func (r *Result) Merge(c Contribution) {
	if r.Confirmed == nil {
		r.Confirmed = map[string]struct{}{}
	}
	if r.Suspect == nil {
		r.Suspect = map[string]struct{}{}
	}
	for id := range c.Confirmed {
		r.Confirmed[id] = struct{}{}
	}
	for id := range c.Suspect {
		r.Suspect[id] = struct{}{}
	}
	r.Normalize()
}

// CopyMap shallow-copies a peer id set. Nil in → nil out.
func CopyMap(in map[string]struct{}) map[string]struct{} {
	if in == nil {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

// UnionMaps returns a∪b (never nil).
func UnionMaps(a, b map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}

// Subtract returns a \ b (never nil).
func Subtract(a, b map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(a))
	for k := range a {
		if _, ok := b[k]; !ok {
			out[k] = struct{}{}
		}
	}
	return out
}

// ApplyAmbiguousMask applies policy to cohort = errSenders \ confirmed.
// Returns an additional Contribution to merge (may be empty).
func ApplyAmbiguousMask(policy AmbiguousMaskPolicy, errSenders, confirmed map[string]struct{}) Contribution {
	cohort := Subtract(errSenders, confirmed)
	if len(cohort) == 0 {
		return Contribution{}
	}
	switch ResolvePolicy(policy) {
	case SuspectNone:
		return Contribution{}
	case ConfirmAllErr:
		return FromConfirmed(cohort)
	default: // SuspectAllErr
		return FromSuspect(cohort)
	}
}
