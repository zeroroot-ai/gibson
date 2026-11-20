// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package jobnode

import (
	"testing"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

func TestCountermeasureOf(t *testing.T) {
	withKey := &jobpb.JobSpec{Context: map[string]*commonpb.TypedValue{
		CountermeasureContextKey: {Kind: &commonpb.TypedValue_StringValue{StringValue: "D3-FA"}},
	}}
	if got := countermeasureOf(withKey); got != "D3-FA" {
		t.Errorf("countermeasureOf = %q, want D3-FA", got)
	}
	// A spec with no key, a nil spec and a key of another type give "".
	wrongType := &jobpb.JobSpec{Context: map[string]*commonpb.TypedValue{
		CountermeasureContextKey: {Kind: &commonpb.TypedValue_IntValue{IntValue: 3}},
	}}
	for name, spec := range map[string]*jobpb.JobSpec{"no key": {}, "nil spec": nil, "wrong type": wrongType} {
		if got := countermeasureOf(spec); got != "" {
			t.Errorf("%s: countermeasureOf = %q, want empty", name, got)
		}
	}
}
