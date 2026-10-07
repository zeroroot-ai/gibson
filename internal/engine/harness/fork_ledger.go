// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
)

// ForkDispatch is the dispatch of one fork or one sandbox restored from a
// snapshot: the values that a launch gives a process through its
// environment. The sandbox gets them from ClaimFork (ADR-0169, D74, D80).
// It holds no grant: ClaimFork mints a new grant for the claimed task.
type ForkDispatch struct {
	SandboxID    string `json:"sandbox_id"`
	Tenant       string `json:"tenant"`
	AgentName    string `json:"agent_name"`
	MissionID    string `json:"mission_id"`
	MissionRunID string `json:"mission_run_id"`
	AgentRunID   string `json:"agent_run_id"`
	NodeID       string `json:"node_id"`
	Model        string `json:"model"`
	// TaskB64 is the base64 protojson of the task of the fork.
	TaskB64 string `json:"task_b64"`
}

// ForkLedger records which grant a fork came from, so the callback service
// can refuse the grant of a source outside the source sandbox and serve
// each fork its own dispatch once.
type ForkLedger interface {
	// BeginFork marks the grant of a source as forked before setec starts
	// the forks. From then on the grant works only in the source sandbox, and
	// a claim that comes before RecordForks gets ErrForkPending.
	BeginFork(ctx context.Context, sourceJTI, sourceSandboxID string, ttl time.Duration) error
	// RecordForks records the forks of the source sandbox whose grant has
	// the id sourceJTI. ttl bounds how long the record lives.
	RecordForks(ctx context.Context, sourceJTI, sourceSandboxID string, forks []ForkDispatch, ttl time.Duration) error
	// ForkedSource returns the source sandbox of a grant that has forks.
	// forked is false for a grant with no fork.
	ForkedSource(ctx context.Context, sourceJTI string) (sourceSandboxID string, forked bool, err error)
	// RecordStart records the dispatch of a sandbox that the daemon asked
	// setec to start, as a fork or from a snapshot (D80). Only that sandbox
	// can claim it.
	RecordStart(ctx context.Context, d ForkDispatch, ttl time.Duration) error
	// ClaimTarget returns the sandbox and the tenant of the start that a
	// hostname names. ClaimFork verifies the identity token of the caller
	// against them before it claims.
	ClaimTarget(ctx context.Context, hostname string) (ClaimTarget, error)
	// Claim returns the dispatch of the start that a hostname names, one
	// time.
	Claim(ctx context.Context, hostname string) (ForkDispatch, error)
	// ReserveForkSeat records a fork of a caller that waits for the first
	// node of a child mission (gibson#803). Until RecordForks records its
	// dispatch, a claim of the fork gets ErrForkPending.
	ReserveForkSeat(ctx context.Context, seat ForkSeat, ttl time.Duration) error
	// TakeForkSeat returns the waiting fork of a node of a mission, one
	// time. ok is false when the node has no waiting fork.
	TakeForkSeat(ctx context.Context, missionID, nodeID string) (seat ForkSeat, ok bool, err error)
}

// ForkSeat is a fork of a caller sandbox that waits for the first node of
// the child mission that the caller originated (ADR-0169, gibson#803). The
// fork took the network scope of that node at the Fork call.
type ForkSeat struct {
	MissionID string `json:"mission_id"`
	NodeID    string `json:"node_id"`
	Tenant    string `json:"tenant"`
	// AgentName is the agent of the caller. Only that agent can continue the
	// state of the fork.
	AgentName string `json:"agent_name"`
	// SandboxID is the fork.
	SandboxID string `json:"sandbox_id"`
	// SandboxClass is the class of the fork.
	SandboxClass string `json:"sandbox_class"`
	// SourceSandboxID and SourceJTI are the caller sandbox and the id of
	// its grant. The fork claims its dispatch with that grant.
	SourceSandboxID string `json:"source_sandbox_id"`
	SourceJTI       string `json:"source_jti"`
}

// SnapshotLife is the life of a node snapshot of the sandbox checkpoint mode
// and of the start record of a sandbox restored from it (ADR-0170).
const SnapshotLife = 7 * 24 * time.Hour

// ClaimTarget is the sandbox that a start record waits for.
type ClaimTarget struct {
	SandboxID string
	Tenant    string
}

// ErrNotAFork refuses a claim for a sandbox that the daemon did not start.
var ErrNotAFork = errors.New("harness: the daemon started no such sandbox")

// ErrForkPending answers a claim that comes before the forks are recorded.
// The fork retries.
var ErrForkPending = errors.New("harness: the forks of this grant are not recorded yet")

// ErrForkClaimed refuses a second claim of one fork.
var ErrForkClaimed = errors.New("harness: the fork was already claimed")

// hostnameStrip matches each character that a hostname label refuses.
var hostnameStrip = regexp.MustCompile(`[^a-z0-9-]`)

// SandboxHostname is the hostname that setec gives a sandbox: the name part
// of its id "<namespace>/<name>/<uid>", lowercased, with each other
// character made a dash, trimmed to 63 characters. It mirrors
// SanitizeHostname of setec (internal/uniquify), which is not importable.
func SandboxHostname(sandboxID string) string {
	name := sandboxID
	if parts := strings.Split(sandboxID, "/"); len(parts) == 3 {
		name = parts[1]
	}
	s := strings.Trim(hostnameStrip.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-")
	}
	if s == "" {
		s = "setec-sandbox"
	}
	return s
}
