// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"testing"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

func TestNewToolCallID_UsesTheIDOfTheCaller(t *testing.T) {
	info := &harnesspb.ContextInfo{ToolExecutionId: "exec-1"}
	if got := newToolCallID(info); got != "exec-1" {
		t.Fatalf("got %q, want the id of the caller", got)
	}
}

func TestNewToolCallID_MintsAFreshIDWhenEmpty(t *testing.T) {
	a := newToolCallID(&harnesspb.ContextInfo{})
	b := newToolCallID(nil)
	if a == "" || b == "" || a == b {
		t.Fatalf("want two distinct fresh ids, got %q and %q", a, b)
	}
}

func TestQueuedToolCallID_IsStableAndUnique(t *testing.T) {
	first, again := queuedToolCallID("job-1", 0), queuedToolCallID("job-1", 0)
	if first != again {
		t.Fatal("the id of one input must not change")
	}
	seen := map[string]bool{}
	for _, job := range []string{"job-1", "job-2"} {
		for i := range 3 {
			id := queuedToolCallID(job, i)
			if seen[id] {
				t.Fatalf("duplicate id %s", id)
			}
			seen[id] = true
		}
	}
}
