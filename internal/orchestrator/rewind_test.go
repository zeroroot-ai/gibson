package orchestrator

import (
	"context"
	"testing"

	manifestpb "github.com/zero-day-ai/sdk/api/gen/gibson/manifest/v1"
)

func TestDispatchInFlightTool(t *testing.T) {
	tt := []struct {
		name string
		in   InFlightTool
		want IdempotencyAction
	}{
		{
			name: "at_most_once -> skip_failed",
			in: InFlightTool{
				NodeID:      "n1",
				Idempotency: manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_MOST_ONCE,
			},
			want: IdempotencyActionSkipFailed,
		},
		{
			name: "at_least_once -> retry",
			in: InFlightTool{
				NodeID:      "n1",
				Idempotency: manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_LEAST_ONCE,
			},
			want: IdempotencyActionRetry,
		},
		{
			name: "unspecified -> retry (defaults to AT_LEAST_ONCE per R6.6)",
			in: InFlightTool{
				NodeID:      "n1",
				Idempotency: manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_UNSPECIFIED,
			},
			want: IdempotencyActionRetry,
		},
		{
			name: "exactly_once with token -> resume_with_token",
			in: InFlightTool{
				NodeID:          "n1",
				ResumptionToken: "tok-abc",
				Idempotency:     manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_EXACTLY_ONCE,
			},
			want: IdempotencyActionResumeWithToken,
		},
		{
			name: "exactly_once without token -> fail_mission",
			in: InFlightTool{
				NodeID:      "n1",
				Idempotency: manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_EXACTLY_ONCE,
			},
			want: IdempotencyActionFailMission,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := DispatchInFlightTool(tc.in)
			if got != tc.want {
				t.Errorf("DispatchInFlightTool = %v, want %v", got, tc.want)
			}
		})
	}
}

type captureEmitter struct {
	calls []struct {
		MissionID string
		ToolNode  string
		Mode      manifestpb.ToolIdempotency
		Action    IdempotencyAction
	}
}

func (c *captureEmitter) OnToolDispatch(_ context.Context, missionID, nodeID string, mode manifestpb.ToolIdempotency, action IdempotencyAction) {
	c.calls = append(c.calls, struct {
		MissionID string
		ToolNode  string
		Mode      manifestpb.ToolIdempotency
		Action    IdempotencyAction
	}{missionID, nodeID, mode, action})
}

func TestRewindDispatcher_RewindEmitsPerTool(t *testing.T) {
	emitter := &captureEmitter{}
	d := NewRewindDispatcher(emitter)
	err := d.Rewind(context.Background(), "mission-1", []InFlightTool{
		{NodeID: "n1", Idempotency: manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_MOST_ONCE},
		{NodeID: "n2", Idempotency: manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_LEAST_ONCE},
	})
	if err != nil {
		t.Fatalf("rewind unexpectedly errored: %v", err)
	}
	if len(emitter.calls) != 2 {
		t.Fatalf("expected 2 emitter calls, got %d", len(emitter.calls))
	}
	if emitter.calls[0].Action != IdempotencyActionSkipFailed {
		t.Errorf("first call action = %v, want skip_failed", emitter.calls[0].Action)
	}
	if emitter.calls[1].Action != IdempotencyActionRetry {
		t.Errorf("second call action = %v, want retry", emitter.calls[1].Action)
	}
}

func TestRewindDispatcher_FailMissionOnExactlyOnceWithoutToken(t *testing.T) {
	d := NewRewindDispatcher(nil)
	err := d.Rewind(context.Background(), "mission-1", []InFlightTool{
		{NodeID: "n1", Idempotency: manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_EXACTLY_ONCE},
	})
	if err == nil {
		t.Fatalf("expected error for EXACTLY_ONCE without resumption token")
	}
}

func TestNormalizeIdempotency(t *testing.T) {
	if got := NormalizeIdempotency(manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_UNSPECIFIED); got != manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_LEAST_ONCE {
		t.Errorf("UNSPECIFIED should normalize to AT_LEAST_ONCE, got %v", got)
	}
	if got := NormalizeIdempotency(manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_MOST_ONCE); got != manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_MOST_ONCE {
		t.Errorf("AT_MOST_ONCE should pass through, got %v", got)
	}
}

func TestResolveIdempotencyFromString(t *testing.T) {
	tt := []struct {
		s    string
		want manifestpb.ToolIdempotency
	}{
		{"AT_MOST_ONCE", manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_MOST_ONCE},
		{"AT_LEAST_ONCE", manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_AT_LEAST_ONCE},
		{"EXACTLY_ONCE", manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_EXACTLY_ONCE},
		{"", manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_UNSPECIFIED},
		{"garbage", manifestpb.ToolIdempotency_TOOL_IDEMPOTENCY_UNSPECIFIED},
	}
	for _, tc := range tt {
		if got := ResolveIdempotencyFromString(tc.s); got != tc.want {
			t.Errorf("ResolveIdempotencyFromString(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}
