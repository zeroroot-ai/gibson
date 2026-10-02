// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"
)

// A finding's scope is the target UUID, resolved server-side from the harness's
// Target(). A for_each instance therefore has to be handed a harness that
// reports ITS target, and the instance id is where that target comes from.
//
// If this derivation breaks, findings from every instance carry the mission's
// primary target and several hosts merge onto one coordinate — which is the
// failure observationAttribution refuses an empty scope to prevent, arriving by
// a different route and without the refusal (gibson#526).
func TestInstanceTargetID(t *testing.T) {
	cases := []struct {
		name   string
		workID string
		want   string
	}{
		{
			name:   "a for_each instance yields its target",
			workID: "scan#11111111-1111-1111-1111-111111111111",
			want:   "11111111-1111-1111-1111-111111111111",
		},
		{
			name:   "an ordinary node yields nothing, so the harness is unchanged",
			workID: "scan",
			want:   "",
		},
		{
			name:   "an empty work id yields nothing rather than panicking",
			workID: "",
			want:   "",
		},
		{
			name:   "a separator with no target yields nothing, never an empty scope",
			workID: "scan#",
			want:   "",
		},
		{
			name: "a template id containing the separator takes the LAST one, " +
				"because the target is always the suffix",
			workID: "scan#weird#22222222-2222-2222-2222-222222222222",
			want:   "22222222-2222-2222-2222-222222222222",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := instanceTargetID(tc.workID); got != tc.want {
				t.Errorf("instanceTargetID(%q) = %q, want %q", tc.workID, got, tc.want)
			}
		})
	}
}

// The id the projection writes and the id the dispatcher reads must agree. They
// are two halves of one contract, and a test that only checked one direction
// would pass while they drifted.
func TestInstanceIDRoundTrips(t *testing.T) {
	const target = "33333333-3333-3333-3333-333333333333"
	id := instanceID("scan", target)
	if got := instanceTargetID(id); got != target {
		t.Errorf("round trip: instanceTargetID(instanceID(%q)) = %q, want %q", target, got, target)
	}
}
