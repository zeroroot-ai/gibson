// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agent

import "testing"

func TestMinLimit(t *testing.T) {
	cases := []struct{ a, b, want int32 }{
		{0, 0, 0}, {5, 0, 5}, {0, 5, 5}, {5, 9, 5}, {9, 5, 5}, {-1, 7, 7}, {-1, -2, 0},
	}
	for _, tc := range cases {
		if got := MinLimit(tc.a, tc.b); got != tc.want {
			t.Errorf("MinLimit(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
