// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package helpers — plugin_install.go
//
// Polls PluginAdminService/ListPluginInstalls for one plugin's status. The
// plugin secret revocation exit test (gibson#154) asserts two things with it:
// the status a running plugin reports stays serving while nothing changes,
// and a revoked secret turns it degraded within one heartbeat interval plus
// the event stream's latency. Every poll is kept, so a failure prints what
// the daemon said at each second instead of only the last answer.
//
// No build tag: the merge gate compiles and unit-tests this file against a
// fake lister (plugin_install_test.go). The cluster-bound caller lives behind
// -tags=e2e.
package helpers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	pluginadminv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/pluginadmin/v1"
	"google.golang.org/grpc"
)

// PluginInstallLister is the one PluginAdminService call the poller needs.
// *pluginadminv1.pluginAdminServiceClient satisfies it.
type PluginInstallLister interface {
	ListPluginInstalls(ctx context.Context, in *pluginadminv1.ListPluginInstallsRequest, opts ...grpc.CallOption) (*pluginadminv1.ListPluginInstallsResponse, error)
}

// PluginInstallObservation is one poll of ListPluginInstalls.
type PluginInstallObservation struct {
	At time.Time
	// Install is the install the poll selected, nil when none matched.
	Install *pluginadminv1.PluginInstallSummary
	// Err is the RPC error, nil on a successful poll.
	Err error
}

// Status is the observed status, UNSPECIFIED when no install matched or the
// poll failed.
func (o PluginInstallObservation) Status() pluginadminv1.PluginInstallStatus {
	if o.Install == nil {
		return pluginadminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_UNSPECIFIED
	}
	return o.Install.GetStatus()
}

func (o PluginInstallObservation) String() string {
	at := o.At.UTC().Format("15:04:05.000")
	switch {
	case o.Err != nil:
		return fmt.Sprintf("%s ListPluginInstalls error: %v", at, o.Err)
	case o.Install == nil:
		return at + " no matching install"
	default:
		return fmt.Sprintf("%s install=%s name=%s status=%s last_heartbeat=%s bound=%v",
			at, o.Install.GetInstallId(), o.Install.GetName(), o.Install.GetStatus(),
			time.Unix(o.Install.GetLastHeartbeatAtUnix(), 0).UTC().Format(time.RFC3339),
			o.Install.GetBoundSecretRefs())
	}
}

// FormatObservations renders a poll history one line per poll, for a failure
// message.
func FormatObservations(obs []PluginInstallObservation) string {
	lines := make([]string, 0, len(obs))
	for _, o := range obs {
		lines = append(lines, "  "+o.String())
	}
	return strings.Join(lines, "\n")
}

// ObservePluginInstall lists the installs named name once and selects the one
// with installID. An empty installID selects the first install in the
// reply that reports want, so a caller that does not yet know the install can
// find the live one among stale rows a re-enrolled plugin leaves behind.
func ObservePluginInstall(ctx context.Context, lister PluginInstallLister, name, installID string, want pluginadminv1.PluginInstallStatus) PluginInstallObservation {
	obs := PluginInstallObservation{At: time.Now()}
	resp, err := lister.ListPluginInstalls(ctx, &pluginadminv1.ListPluginInstallsRequest{NameFilter: name})
	if err != nil {
		obs.Err = err
		return obs
	}
	for _, inst := range resp.GetInstalls() {
		if inst.GetName() != name {
			continue
		}
		if installID != "" {
			if inst.GetInstallId() == installID {
				obs.Install = inst
				return obs
			}
			continue
		}
		if inst.GetStatus() == want {
			obs.Install = inst
			return obs
		}
		// No match yet: keep the last install seen so the history names
		// what the daemon reported instead of "no matching install".
		obs.Install = inst
	}
	return obs
}

// ErrStatusWindowElapsed reports that the wanted status did not appear within
// the window.
var ErrStatusWindowElapsed = errors.New("plugin install status window elapsed")

// WaitForPluginInstallStatus polls every poll until the install named name
// (and installID, when given) reports want, or window elapses. It returns
// the matching install and every observation made.
func WaitForPluginInstallStatus(ctx context.Context, lister PluginInstallLister, name, installID string, want pluginadminv1.PluginInstallStatus, window, poll time.Duration) (*pluginadminv1.PluginInstallSummary, []PluginInstallObservation, error) {
	deadline := time.Now().Add(window)
	var history []PluginInstallObservation
	for {
		obs := ObservePluginInstall(ctx, lister, name, installID, want)
		history = append(history, obs)
		if obs.Err == nil && obs.Install != nil && obs.Install.GetStatus() == want {
			return obs.Install, history, nil
		}
		if !time.Now().Add(poll).Before(deadline) {
			return nil, history, fmt.Errorf("%w: %s did not report %s within %s (%d polls)",
				ErrStatusWindowElapsed, name, want, window, len(history))
		}
		select {
		case <-ctx.Done():
			return nil, history, fmt.Errorf("waiting for %s to report %s: %w", name, want, ctx.Err())
		case <-time.After(poll):
		}
	}
}

// ErrStatusChanged reports that an install left the status it had to hold.
var ErrStatusChanged = errors.New("plugin install status changed")

// HoldPluginInstallStatus polls every poll for the whole window and returns
// ErrStatusChanged on the first observation in which the install does not
// report want. A poll error ends the hold too: a status nobody can read is
// not a status that held.
func HoldPluginInstallStatus(ctx context.Context, lister PluginInstallLister, name, installID string, want pluginadminv1.PluginInstallStatus, window, poll time.Duration) ([]PluginInstallObservation, error) {
	if installID == "" {
		return nil, errors.New("HoldPluginInstallStatus: installID is required")
	}
	deadline := time.Now().Add(window)
	var history []PluginInstallObservation
	for {
		obs := ObservePluginInstall(ctx, lister, name, installID, want)
		history = append(history, obs)
		if obs.Err != nil {
			return history, fmt.Errorf("poll %d: %w", len(history), obs.Err)
		}
		if obs.Install == nil || obs.Install.GetStatus() != want {
			return history, fmt.Errorf("%w: poll %d saw %s, want %s", ErrStatusChanged, len(history), obs.Status(), want)
		}
		if !time.Now().Before(deadline) {
			return history, nil
		}
		select {
		case <-ctx.Done():
			return history, fmt.Errorf("holding %s at %s: %w", name, want, ctx.Err())
		case <-time.After(poll):
		}
	}
}

// ErrNoHeartbeat reports that an install's last_heartbeat_at did not move
// within the window.
var ErrNoHeartbeat = errors.New("plugin install heartbeat did not advance")

// WaitForPluginInstallHeartbeat polls until the install's
// last_heartbeat_at is later than sinceUnix, or window elapses. Registration
// writes a serving status with a 90-second TTL before the plugin resolves
// its startup secrets, so a plugin that died right after registering reads
// SERVING for a minute and a half. A heartbeat that moved is the proof a
// process is alive behind the status (run 35635251315).
func WaitForPluginInstallHeartbeat(ctx context.Context, lister PluginInstallLister, name, installID string, sinceUnix int64, window, poll time.Duration) (*pluginadminv1.PluginInstallSummary, []PluginInstallObservation, error) {
	if installID == "" {
		return nil, nil, errors.New("WaitForPluginInstallHeartbeat: installID is required")
	}
	deadline := time.Now().Add(window)
	var history []PluginInstallObservation
	for {
		obs := ObservePluginInstall(ctx, lister, name, installID, pluginadminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_SERVING)
		history = append(history, obs)
		if obs.Err == nil && obs.Install != nil && obs.Install.GetLastHeartbeatAtUnix() > sinceUnix {
			return obs.Install, history, nil
		}
		if !time.Now().Add(poll).Before(deadline) {
			return nil, history, fmt.Errorf("%w: %s/%s stayed at last_heartbeat_at<=%d for %s (%d polls)",
				ErrNoHeartbeat, name, installID, sinceUnix, window, len(history))
		}
		select {
		case <-ctx.Done():
			return nil, history, fmt.Errorf("waiting for a heartbeat from %s: %w", installID, ctx.Err())
		case <-time.After(poll):
		}
	}
}
