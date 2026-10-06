// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// ForkDispatch is the dispatch of one fork: the values that a launch gives
// a process through its environment. A fork gets them from ClaimFork
// (ADR-0169, D74, sdk#248).
type ForkDispatch struct {
	SandboxID    string `json:"sandbox_id"`
	Grant        string `json:"grant"`
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
	// Claim returns the dispatch of one fork of the grant, one time. The
	// fork is the sandbox id "<namespace>/<name>/<uid>" that setec verified
	// from the identity token of the caller (setec#235), never a value that
	// the process sent.
	Claim(ctx context.Context, sourceJTI, forkSandboxID string) (ForkDispatch, error)
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

// ErrNotAFork refuses a claim for a sandbox that is not a fork of the grant.
var ErrNotAFork = errors.New("harness: the sandbox is not a fork of this grant")

// ErrForkPending answers a claim that comes before the forks are recorded.
// The fork retries.
var ErrForkPending = errors.New("harness: the forks of this grant are not recorded yet")

// ErrForkClaimed refuses a second claim of one fork.
var ErrForkClaimed = errors.New("harness: the fork was already claimed")

// RedisForkLedger keeps the ledger in Redis, so each daemon replica sees the
// forks that another replica made. One hash holds one source grant: the
// field "source" names the source sandbox, "d:<fork id>" holds the dispatch
// of a fork, and "c:<fork id>" marks a claimed fork.
type RedisForkLedger struct {
	client redis.UniversalClient
}

// NewRedisForkLedger returns a ledger over client.
func NewRedisForkLedger(client redis.UniversalClient) *RedisForkLedger {
	return &RedisForkLedger{client: client}
}

func forkLedgerKey(jti string) string { return "gibson:fork:" + jti }

func forkSeatKey(missionID, nodeID string) string {
	return "gibson:forkseat:" + missionID + ":" + nodeID
}

// BeginFork implements ForkLedger.
func (l *RedisForkLedger) BeginFork(ctx context.Context, sourceJTI, sourceSandboxID string, ttl time.Duration) error {
	if sourceJTI == "" || sourceSandboxID == "" {
		return errors.New("harness: a fork record needs the grant id and the source sandbox")
	}
	key := forkLedgerKey(sourceJTI)
	pipe := l.client.TxPipeline()
	pipe.HSet(ctx, key, "source", sourceSandboxID, "pending", 1)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("begin fork record: %w", err)
	}
	return nil
}

// RecordForks implements ForkLedger.
func (l *RedisForkLedger) RecordForks(ctx context.Context, sourceJTI, sourceSandboxID string, forks []ForkDispatch, ttl time.Duration) error {
	if sourceJTI == "" || sourceSandboxID == "" {
		return errors.New("harness: a fork record needs the grant id and the source sandbox")
	}
	fields := make(map[string]any, len(forks)+1)
	fields["source"] = sourceSandboxID
	for _, f := range forks {
		raw, err := json.Marshal(f)
		if err != nil {
			return fmt.Errorf("encode fork dispatch: %w", err)
		}
		fields["d:"+f.SandboxID] = raw
	}
	key := forkLedgerKey(sourceJTI)
	pipe := l.client.TxPipeline()
	pending := make([]string, 0, len(forks)+1)
	pending = append(pending, "pending")
	for _, f := range forks {
		pending = append(pending, "p:"+f.SandboxID)
	}
	pipe.HSet(ctx, key, fields)
	pipe.HDel(ctx, key, pending...)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("record forks: %w", err)
	}
	return nil
}

// ForkedSource implements ForkLedger.
func (l *RedisForkLedger) ForkedSource(ctx context.Context, sourceJTI string) (sourceSandboxID string, forked bool, err error) {
	src, err := l.client.HGet(ctx, forkLedgerKey(sourceJTI), "source").Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read fork record: %w", err)
	}
	return src, true, nil
}

// Claim implements ForkLedger.
func (l *RedisForkLedger) Claim(ctx context.Context, sourceJTI, forkSandboxID string) (ForkDispatch, error) {
	key := forkLedgerKey(sourceJTI)
	if forkSandboxID == "" {
		return ForkDispatch{}, ErrNotAFork
	}
	raw, err := l.client.HGet(ctx, key, "d:"+forkSandboxID).Bytes()
	if errors.Is(err, redis.Nil) {
		marks, perr := l.client.HMGet(ctx, key, "pending", "p:"+forkSandboxID).Result()
		if perr != nil {
			return ForkDispatch{}, fmt.Errorf("read fork record: %w", perr)
		}
		for _, m := range marks {
			if m != nil {
				return ForkDispatch{}, ErrForkPending
			}
		}
		return ForkDispatch{}, ErrNotAFork
	}
	if err != nil {
		return ForkDispatch{}, fmt.Errorf("read fork dispatch: %w", err)
	}
	first, err := l.client.HSetNX(ctx, key, "c:"+forkSandboxID, 1).Result()
	if err != nil {
		return ForkDispatch{}, fmt.Errorf("mark fork claimed: %w", err)
	}
	if !first {
		return ForkDispatch{}, ErrForkClaimed
	}
	var d ForkDispatch
	if err := json.Unmarshal(raw, &d); err != nil {
		return ForkDispatch{}, fmt.Errorf("decode fork dispatch: %w", err)
	}
	return d, nil
}

// ReserveForkSeat implements ForkLedger. The fork counts as pending in the
// record of the source grant first, so a claim never finds it unknown.
func (l *RedisForkLedger) ReserveForkSeat(ctx context.Context, seat ForkSeat, ttl time.Duration) error {
	if seat.SourceJTI == "" || seat.SourceSandboxID == "" || seat.SandboxID == "" || seat.MissionID == "" || seat.NodeID == "" {
		return errors.New("harness: a fork seat needs the grant id, the source, the fork, the mission and the node")
	}
	raw, err := json.Marshal(seat)
	if err != nil {
		return fmt.Errorf("encode fork seat: %w", err)
	}
	key := forkLedgerKey(seat.SourceJTI)
	pipe := l.client.TxPipeline()
	pipe.HSet(ctx, key, "source", seat.SourceSandboxID, "p:"+seat.SandboxID, 1)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("record pending fork: %w", err)
	}
	if err := l.client.Set(ctx, forkSeatKey(seat.MissionID, seat.NodeID), raw, ttl).Err(); err != nil {
		return fmt.Errorf("record fork seat: %w", err)
	}
	return nil
}

// TakeForkSeat implements ForkLedger.
func (l *RedisForkLedger) TakeForkSeat(ctx context.Context, missionID, nodeID string) (ForkSeat, bool, error) {
	raw, err := l.client.GetDel(ctx, forkSeatKey(missionID, nodeID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return ForkSeat{}, false, nil
	}
	if err != nil {
		return ForkSeat{}, false, fmt.Errorf("take fork seat: %w", err)
	}
	var seat ForkSeat
	if err := json.Unmarshal(raw, &seat); err != nil {
		return ForkSeat{}, false, fmt.Errorf("decode fork seat: %w", err)
	}
	return seat, true, nil
}

// hostnameStrip matches each character that a hostname label refuses.
var hostnameStrip = regexp.MustCompile(`[^a-z0-9-]`)

// sandboxHostname is the hostname that setec gives a sandbox: the name part
// of its id "<namespace>/<name>/<uid>", lowercased, with each other
// character made a dash, trimmed to 63 characters. It mirrors
// SanitizeHostname of setec (internal/uniquify), which is not importable.
func sandboxHostname(sandboxID string) string {
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
