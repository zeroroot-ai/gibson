// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"errors"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"github.com/zeroroot-ai/gibson/internal/engine/agentwire"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func TestAgentWorkFailure_KeepsTheTaskState(t *testing.T) {
	wrap := func(s a2a.TaskState) error {
		return types.WrapError("x", "agent ended", &agentwire.StateError{State: s, Message: "why"})
	}
	cases := []struct {
		name string
		err  error
		want brain.WorkCompleted
	}{
		{"canceled", wrap(a2a.TaskStateCanceled),
			brain.WorkCompleted{ID: "w", RunID: "r", State: brain.WorkCanceled, Err: "why"}},
		{"input required", wrap(a2a.TaskStateInputRequired),
			brain.WorkCompleted{ID: "w", RunID: "r", State: brain.WorkInputRequired, Err: "why"}},
		{"auth required", wrap(a2a.TaskStateAuthRequired),
			brain.WorkCompleted{ID: "w", RunID: "r", State: brain.WorkInputRequired, Err: "why"}},
		{"plain error", errors.New("boom"), brain.WorkCompleted{ID: "w", RunID: "r", Err: "boom"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentWorkFailure("w", "r", tc.err); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
