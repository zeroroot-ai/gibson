// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package helpers

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pluginadminv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/pluginadmin/v1"
	"google.golang.org/grpc"
)

const (
	serving  = pluginadminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_SERVING
	degraded = pluginadminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_DEGRADED
)

// scriptedLister answers ListPluginInstalls from a script, one reply per
// call; the last reply repeats once the script runs out.
type scriptedLister struct {
	replies [][]*pluginadminv1.PluginInstallSummary
	errs    []error
	calls   int
}

func (s *scriptedLister) ListPluginInstalls(_ context.Context, in *pluginadminv1.ListPluginInstallsRequest, _ ...grpc.CallOption) (*pluginadminv1.ListPluginInstallsResponse, error) {
	i := s.calls
	s.calls++
	if i < len(s.errs) && s.errs[i] != nil {
		return nil, s.errs[i]
	}
	if i >= len(s.replies) {
		i = len(s.replies) - 1
	}
	var out []*pluginadminv1.PluginInstallSummary
	for _, inst := range s.replies[i] {
		if in.GetNameFilter() == "" || inst.GetName() == in.GetNameFilter() {
			out = append(out, inst)
		}
	}
	return &pluginadminv1.ListPluginInstallsResponse{Installs: out}, nil
}

func install(id string, st pluginadminv1.PluginInstallStatus) *pluginadminv1.PluginInstallSummary {
	return &pluginadminv1.PluginInstallSummary{InstallId: id, Name: "github", Status: st, BoundSecretRefs: []string{"cred:github_token"}}
}

// TestWaitForPluginInstallStatus_DegradedArrivesWithinTheWindow is the
// gibson#154 assertion against a fake: serving, serving, degraded. The wait
// returns the degraded install and a history of three polls.
func TestWaitForPluginInstallStatus_DegradedArrivesWithinTheWindow(t *testing.T) {
	t.Parallel()
	l := &scriptedLister{replies: [][]*pluginadminv1.PluginInstallSummary{
		{install("i1", serving)}, {install("i1", serving)}, {install("i1", degraded)},
	}}
	got, hist, err := WaitForPluginInstallStatus(context.Background(), l, "github", "i1", degraded, time.Second, time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForPluginInstallStatus: %v\n%s", err, FormatObservations(hist))
	}
	if got.GetInstallId() != "i1" || got.GetStatus() != degraded || len(hist) != 3 {
		t.Fatalf("got %v after %d polls", got, len(hist))
	}
}

// TestWaitForPluginInstallStatus_WindowElapses: a plugin that never turns
// degraded fails with the window error and the full history, which is the
// message the exit test prints.
func TestWaitForPluginInstallStatus_WindowElapses(t *testing.T) {
	t.Parallel()
	l := &scriptedLister{replies: [][]*pluginadminv1.PluginInstallSummary{{install("i1", serving)}}}
	_, hist, err := WaitForPluginInstallStatus(context.Background(), l, "github", "i1", degraded, 30*time.Millisecond, 5*time.Millisecond)
	if !errors.Is(err, ErrStatusWindowElapsed) {
		t.Fatalf("err = %v, want ErrStatusWindowElapsed", err)
	}
	if len(hist) < 3 || !strings.Contains(FormatObservations(hist), "status=PLUGIN_INSTALL_STATUS_SERVING") {
		t.Fatalf("history must name every poll:\n%s", FormatObservations(hist))
	}
}

// TestWaitForPluginInstallStatus_FindsTheLiveInstallAmongStaleRows: with no
// install id, the wait picks the install that reports the wanted status and
// skips a stale unreachable row the same plugin left behind.
func TestWaitForPluginInstallStatus_FindsTheLiveInstallAmongStaleRows(t *testing.T) {
	t.Parallel()
	stale := install("old", pluginadminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_UNREACHABLE)
	other := &pluginadminv1.PluginInstallSummary{InstallId: "x", Name: "gitlab", Status: serving}
	l := &scriptedLister{replies: [][]*pluginadminv1.PluginInstallSummary{{other, stale, install("new", serving)}}}
	got, _, err := WaitForPluginInstallStatus(context.Background(), l, "github", "", serving, time.Second, time.Millisecond)
	if err != nil || got.GetInstallId() != "new" {
		t.Fatalf("got %v, %v; want the serving install", got, err)
	}
}

// TestWaitForPluginInstallStatus_ToleratesAPollError: one failed RPC is one
// observation, not the verdict.
func TestWaitForPluginInstallStatus_ToleratesAPollError(t *testing.T) {
	t.Parallel()
	l := &scriptedLister{
		replies: [][]*pluginadminv1.PluginInstallSummary{{install("i1", serving)}, {install("i1", degraded)}},
		errs:    []error{errors.New("unavailable")},
	}
	got, hist, err := WaitForPluginInstallStatus(context.Background(), l, "github", "i1", degraded, time.Second, time.Millisecond)
	if err != nil || got.GetStatus() != degraded || hist[0].Err == nil {
		t.Fatalf("got %v, %v, history %s", got, err, FormatObservations(hist))
	}
}

// TestHoldPluginInstallStatus_HoldsForTheWholeWindow is the negative arm:
// nothing revoked, every poll says serving, the hold returns no error.
func TestHoldPluginInstallStatus_HoldsForTheWholeWindow(t *testing.T) {
	t.Parallel()
	l := &scriptedLister{replies: [][]*pluginadminv1.PluginInstallSummary{{install("i1", serving)}}}
	hist, err := HoldPluginInstallStatus(context.Background(), l, "github", "i1", serving, 30*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("HoldPluginInstallStatus: %v", err)
	}
	if len(hist) < 3 {
		t.Fatalf("expected several polls over the window, got %d", len(hist))
	}
}

// TestHoldPluginInstallStatus_FailsOnTheFirstDeviation: a status that flips
// with nothing revoked is the bug the negative arm exists to catch, and a
// poll error ends the hold rather than counting as a pass.
func TestHoldPluginInstallStatus_FailsOnTheFirstDeviation(t *testing.T) {
	t.Parallel()
	l := &scriptedLister{replies: [][]*pluginadminv1.PluginInstallSummary{{install("i1", serving)}, {install("i1", degraded)}}}
	hist, err := HoldPluginInstallStatus(context.Background(), l, "github", "i1", serving, time.Second, time.Millisecond)
	if !errors.Is(err, ErrStatusChanged) || len(hist) != 2 {
		t.Fatalf("err = %v after %d polls, want ErrStatusChanged on poll 2", err, len(hist))
	}
	gone := &scriptedLister{replies: [][]*pluginadminv1.PluginInstallSummary{{}}}
	if _, err := HoldPluginInstallStatus(context.Background(), gone, "github", "i1", serving, time.Second, time.Millisecond); !errors.Is(err, ErrStatusChanged) {
		t.Fatalf("a vanished install must end the hold, got %v", err)
	}
	failing := &scriptedLister{replies: [][]*pluginadminv1.PluginInstallSummary{{install("i1", serving)}}, errs: []error{errors.New("unavailable")}}
	if _, err := HoldPluginInstallStatus(context.Background(), failing, "github", "i1", serving, time.Second, time.Millisecond); err == nil {
		t.Fatal("a poll error must end the hold")
	}
	if _, err := HoldPluginInstallStatus(context.Background(), l, "github", "", serving, time.Second, time.Millisecond); err == nil {
		t.Fatal("a hold with no install id has nothing to hold")
	}
}

// TestWaitForPluginInstallHeartbeat: a status a dead plugin left behind
// does not count; the heartbeat time has to move past the registration
// time, and the wait fails with the history when it never does.
func TestWaitForPluginInstallHeartbeat(t *testing.T) {
	t.Parallel()
	stale := install("i1", serving)
	stale.LastHeartbeatAtUnix = 100
	fresh := install("i1", serving)
	fresh.LastHeartbeatAtUnix = 111
	l := &scriptedLister{replies: [][]*pluginadminv1.PluginInstallSummary{{stale}, {stale}, {fresh}}}
	got, hist, err := WaitForPluginInstallHeartbeat(context.Background(), l, "github", "i1", 100, time.Second, time.Millisecond)
	if err != nil || got.GetLastHeartbeatAtUnix() != 111 || len(hist) != 3 {
		t.Fatalf("got %v, %v after %d polls", got, err, len(hist))
	}
	dead := &scriptedLister{replies: [][]*pluginadminv1.PluginInstallSummary{{stale}}}
	_, hist, err = WaitForPluginInstallHeartbeat(context.Background(), dead, "github", "i1", 100, 20*time.Millisecond, 5*time.Millisecond)
	if !errors.Is(err, ErrNoHeartbeat) || len(hist) < 2 {
		t.Fatalf("err = %v after %d polls, want ErrNoHeartbeat", err, len(hist))
	}
	if _, _, err := WaitForPluginInstallHeartbeat(context.Background(), dead, "github", "", 0, time.Second, time.Millisecond); err == nil {
		t.Fatal("a wait with no install id has nothing to watch")
	}
}
