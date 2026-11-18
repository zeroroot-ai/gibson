// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package budget

import "testing"

func TestCostCents(t *testing.T) {
	cases := []struct {
		name    string
		known   bool
		usd     string
		want    int64
		wantErr bool
	}{
		{"unknown cost", false, "0.5", 0, false},
		{"empty cost", true, "", 0, false},
		{"zero", true, "0", 0, false},
		{"a sub-cent call counts one cent", true, "0.0004", 1, false},
		{"a whole cent", true, "0.01", 1, false},
		{"rounds up", true, "0.0123", 2, false},
		{"dollars", true, "2.5", 250, false},
		{"not a number", true, "abc", 0, true},
		{"negative", true, "-1", 0, true},
		{"NaN", true, "NaN", 0, true},
		{"infinite", true, "+Inf", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CostCents(tc.known, tc.usd)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("got %d, %v want %d, err %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
