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

package blame

import "testing"

func TestNormalizeDisjoint(t *testing.T) {
	r := Result{
		Confirmed: map[string]struct{}{"a": {}, "b": {}},
		Suspect:   map[string]struct{}{"b": {}, "c": {}},
	}
	r.Normalize()
	if !r.Disjoint() {
		t.Fatal("expected disjoint after Normalize")
	}
	if _, ok := r.Suspect["b"]; ok {
		t.Fatal("b should leave Suspect (Confirmed wins)")
	}
	if _, ok := r.Suspect["c"]; !ok {
		t.Fatal("c should remain Suspect")
	}
}

func TestApplyAmbiguousMaskSuspectAllErr(t *testing.T) {
	errSenders := map[string]struct{}{"a": {}, "b": {}, "c": {}}
	confirmed := map[string]struct{}{"a": {}}
	c := ApplyAmbiguousMask(SuspectAllErr, errSenders, confirmed)
	if len(c.Confirmed) != 0 {
		t.Fatalf("Confirmed want empty, got %v", c.Confirmed)
	}
	if len(c.Suspect) != 2 {
		t.Fatalf("Suspect want {b,c}, got %v", c.Suspect)
	}
	if _, ok := c.Suspect["a"]; ok {
		t.Fatal("cohort must exclude Confirmed")
	}
}

func TestApplyAmbiguousMaskSuspectNone(t *testing.T) {
	c := ApplyAmbiguousMask(SuspectNone, map[string]struct{}{"a": {}}, nil)
	if len(c.Confirmed)+len(c.Suspect) != 0 {
		t.Fatalf("want empty, got %+v", c)
	}
}

func TestResolvePolicyProdRemapsConfirmAllErr(t *testing.T) {
	if ConfirmAllErrAllowed() {
		t.Skip("debug build honors ConfirmAllErr")
	}
	if got := ResolvePolicy(ConfirmAllErr); got != SuspectAllErr {
		t.Fatalf("prod ResolvePolicy(ConfirmAllErr)=%v, want SuspectAllErr", got)
	}
}
