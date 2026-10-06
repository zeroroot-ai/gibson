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
	// RecordForks records the forks of the source sandbox whose grant has
	// the id sourceJTI. ttl bounds how long the record lives.
	RecordForks(ctx context.Context, sourceJTI, sourceSandboxID string, forks []ForkDispatch, ttl time.Duration) error
	// ForkedSource returns the source sandbox of a grant that has forks.
	// forked is false for a grant with no fork.
	ForkedSource(ctx context.Context, sourceJTI string) (sourceSandboxID string, forked bool, err error)
	// Claim returns the dispatch of one fork of the grant, one time.
	Claim(ctx context.Context, sourceJTI, forkSandboxID string) (ForkDispatch, error)
}

// ErrNotAFork refuses a claim for a sandbox that is not a fork of the grant.
var ErrNotAFork = errors.New("harness: the sandbox is not a fork of this grant")

// ErrForkClaimed refuses a second claim of one fork.
var ErrForkClaimed = errors.New("harness: the fork was already claimed")

// RedisForkLedger keeps the ledger in Redis, so each daemon replica sees the
// forks that another replica made. One hash holds one source grant: the
// field "source" names the source sandbox, "d:<fork id>" holds the dispatch
// of a fork, and "c:<fork id>" marks a claimed fork.
type RedisForkLedger struct {
	client *redis.Client
}

// NewRedisForkLedger returns a ledger over client.
func NewRedisForkLedger(client *redis.Client) *RedisForkLedger {
	return &RedisForkLedger{client: client}
}

func forkLedgerKey(jti string) string { return "gibson:fork:" + jti }

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
	pipe.HSet(ctx, key, fields)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("record forks: %w", err)
	}
	return nil
}

// ForkedSource implements ForkLedger.
func (l *RedisForkLedger) ForkedSource(ctx context.Context, sourceJTI string) (string, bool, error) {
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
	raw, err := l.client.HGet(ctx, key, "d:"+forkSandboxID).Bytes()
	if errors.Is(err, redis.Nil) {
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
