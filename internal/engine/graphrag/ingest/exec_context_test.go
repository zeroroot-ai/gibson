// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import "testing"

// A discovery with no mission is not run-scoped. On the component path
// MissionRunID holds a work item id, which is not a run of any mission, so it
// must not reach the events (gibson#1217).
func TestExecContext_MissionRun(t *testing.T) {
	tests := []struct {
		name string
		ctx  ExecContext
		want string
	}{
		{name: "a mission run", ctx: ExecContext{MissionID: "m1", MissionRunID: "run-1"}, want: "run-1"},
		{name: "no mission, a work item id", ctx: ExecContext{MissionRunID: "work-9"}, want: ""},
		{name: "a mission with no run", ctx: ExecContext{MissionID: "m1"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ctx.missionRun(); got != tt.want {
				t.Errorf("missionRun() = %q, want %q", got, tt.want)
			}
		})
	}
}
