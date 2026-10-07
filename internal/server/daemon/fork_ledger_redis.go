// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

// redisForkLedger keeps the ledger in Redis, so each daemon replica sees the
// forks that another replica made. One hash holds one source grant: the
// field "source" names the source sandbox. One hash holds one started
// sandbox (forkClaimKey).
type redisForkLedger struct {
	client redis.UniversalClient
}

// newRedisForkLedger returns a ledger over client.
func newRedisForkLedger(client redis.UniversalClient) *redisForkLedger {
	return &redisForkLedger{client: client}
}

func forkLedgerKey(jti string) string { return "gibson:fork:" + jti }

// forkClaimKey is the start record of one sandbox, by its hostname. Fields:
// "sandbox_id" and "tenant" name the sandbox, "pending" marks a start whose
// dispatch is not known yet, "d" holds the dispatch, "c" marks the claim.
func forkClaimKey(sandboxID string) string {
	return "gibson:forkclaim:" + harness.SandboxHostname(sandboxID)
}

func forkSeatKey(missionID, nodeID string) string {
	return "gibson:forkseat:" + missionID + ":" + nodeID
}

// BeginFork implements harness.ForkLedger.
func (l *redisForkLedger) BeginFork(ctx context.Context, sourceJTI, sourceSandboxID string, ttl time.Duration) error {
	if sourceJTI == "" || sourceSandboxID == "" {
		return errors.New("fork ledger: a fork record needs the grant id and the source sandbox")
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

// RecordForks implements harness.ForkLedger.
func (l *redisForkLedger) RecordForks(ctx context.Context, sourceJTI, sourceSandboxID string, forks []harness.ForkDispatch, ttl time.Duration) error {
	if sourceJTI == "" || sourceSandboxID == "" {
		return errors.New("fork ledger: a fork record needs the grant id and the source sandbox")
	}
	key := forkLedgerKey(sourceJTI)
	pipe := l.client.TxPipeline()
	pipe.HSet(ctx, key, "source", sourceSandboxID)
	pipe.HDel(ctx, key, "pending")
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("record forks: %w", err)
	}
	for _, f := range forks {
		if err := l.RecordStart(ctx, f, ttl); err != nil {
			return err
		}
	}
	return nil
}

// RecordStart implements harness.ForkLedger.
func (l *redisForkLedger) RecordStart(ctx context.Context, d harness.ForkDispatch, ttl time.Duration) error {
	if d.SandboxID == "" || d.Tenant == "" {
		return errors.New("fork ledger: a start record needs the sandbox and the tenant")
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("encode fork dispatch: %w", err)
	}
	key := forkClaimKey(d.SandboxID)
	pipe := l.client.TxPipeline()
	pipe.HSet(ctx, key, "sandbox_id", d.SandboxID, "tenant", d.Tenant, "d", raw)
	pipe.HDel(ctx, key, "pending")
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("record start of %s: %w", d.SandboxID, err)
	}
	return nil
}

// ClaimTarget implements harness.ForkLedger.
func (l *redisForkLedger) ClaimTarget(ctx context.Context, hostname string) (harness.ClaimTarget, error) {
	if hostname == "" {
		return harness.ClaimTarget{}, harness.ErrNotAFork
	}
	vals, err := l.client.HMGet(ctx, forkClaimKey(hostname), "sandbox_id", "tenant").Result()
	if err != nil {
		return harness.ClaimTarget{}, fmt.Errorf("read start record: %w", err)
	}
	id, _ := vals[0].(string)
	tenant, _ := vals[1].(string)
	if id == "" || tenant == "" {
		return harness.ClaimTarget{}, harness.ErrNotAFork
	}
	return harness.ClaimTarget{SandboxID: id, Tenant: tenant}, nil
}

// ForkedSource implements harness.ForkLedger.
func (l *redisForkLedger) ForkedSource(ctx context.Context, sourceJTI string) (sourceSandboxID string, forked bool, err error) {
	src, err := l.client.HGet(ctx, forkLedgerKey(sourceJTI), "source").Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read fork record: %w", err)
	}
	return src, true, nil
}

// Claim implements harness.ForkLedger.
func (l *redisForkLedger) Claim(ctx context.Context, hostname string) (harness.ForkDispatch, error) {
	if hostname == "" {
		return harness.ForkDispatch{}, harness.ErrNotAFork
	}
	key := forkClaimKey(hostname)
	vals, err := l.client.HMGet(ctx, key, "d", "pending").Result()
	if err != nil {
		return harness.ForkDispatch{}, fmt.Errorf("read start record: %w", err)
	}
	raw, _ := vals[0].(string)
	if raw == "" {
		if vals[1] != nil {
			return harness.ForkDispatch{}, harness.ErrForkPending
		}
		return harness.ForkDispatch{}, harness.ErrNotAFork
	}
	first, err := l.client.HSetNX(ctx, key, "c", 1).Result()
	if err != nil {
		return harness.ForkDispatch{}, fmt.Errorf("mark fork claimed: %w", err)
	}
	if !first {
		return harness.ForkDispatch{}, harness.ErrForkClaimed
	}
	var d harness.ForkDispatch
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return harness.ForkDispatch{}, fmt.Errorf("decode fork dispatch: %w", err)
	}
	return d, nil
}

// ReserveForkSeat implements harness.ForkLedger. The fork counts as pending in the
// record of the source grant first, so a claim never finds it unknown.
func (l *redisForkLedger) ReserveForkSeat(ctx context.Context, seat harness.ForkSeat, ttl time.Duration) error {
	if seat.SourceJTI == "" || seat.SourceSandboxID == "" || seat.SandboxID == "" || seat.MissionID == "" || seat.NodeID == "" {
		return errors.New("fork ledger: a fork seat needs the grant id, the source, the fork, the mission and the node")
	}
	raw, err := json.Marshal(seat)
	if err != nil {
		return fmt.Errorf("encode fork seat: %w", err)
	}
	key := forkLedgerKey(seat.SourceJTI)
	claim := forkClaimKey(seat.SandboxID)
	pipe := l.client.TxPipeline()
	pipe.HSet(ctx, key, "source", seat.SourceSandboxID)
	pipe.Expire(ctx, key, ttl)
	pipe.HSet(ctx, claim, "sandbox_id", seat.SandboxID, "tenant", seat.Tenant, "pending", 1)
	pipe.Expire(ctx, claim, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("record pending fork: %w", err)
	}
	if err := l.client.Set(ctx, forkSeatKey(seat.MissionID, seat.NodeID), raw, ttl).Err(); err != nil {
		return fmt.Errorf("record fork seat: %w", err)
	}
	return nil
}

// TakeForkSeat implements harness.ForkLedger.
func (l *redisForkLedger) TakeForkSeat(ctx context.Context, missionID, nodeID string) (harness.ForkSeat, bool, error) {
	raw, err := l.client.GetDel(ctx, forkSeatKey(missionID, nodeID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return harness.ForkSeat{}, false, nil
	}
	if err != nil {
		return harness.ForkSeat{}, false, fmt.Errorf("take fork seat: %w", err)
	}
	var seat harness.ForkSeat
	if err := json.Unmarshal(raw, &seat); err != nil {
		return harness.ForkSeat{}, false, fmt.Errorf("decode fork seat: %w", err)
	}
	return seat, true, nil
}
