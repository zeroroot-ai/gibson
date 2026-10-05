// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
)

// ErrReplayStateUnavailable is returned when the replay store does not
// answer. The verifier cannot prove that the token is new, so it refuses the
// token. It is its own sentinel, because the token is not at fault: the
// caller maps it to "unavailable", not to "unauthenticated".
var ErrReplayStateUnavailable = errors.New("cgjwt: replay state unavailable")

// ReplayStore records the (kid, jti) pair of each accepted component token.
// All ext-authz replicas share one store, so a token is accepted one time by
// the whole deployment.
type ReplayStore interface {
	// Admit records the pair and reports whether this is its first
	// presentation. The record expires after ttl, which is the time that the
	// token has left. Admit is one atomic set-if-absent operation.
	//
	// An error means that the store gave no answer. The caller must refuse
	// the token.
	Admit(ctx context.Context, kid, jti string, ttl time.Duration) (bool, error)
}

// replayKeyPrefix namespaces the replay records in the shared Redis.
const replayKeyPrefix = "extauthz:cgjwt:replay:"

// replayKey builds the Redis key of a (kid, jti) pair. The key holds the kid,
// so two components that pick the same jti do not collide, and a caller
// cannot use up a jti that it cannot sign for. The length of the kid makes
// the split between kid and jti unambiguous.
func replayKey(kid, jti string) string {
	return replayKeyPrefix + strconv.Itoa(len(kid)) + ":" + kid + ":" + jti
}

// RedisReplayStore is the ReplayStore on Redis.
type RedisReplayStore struct {
	client redis.Cmdable
}

// NewRedisReplayStore returns a ReplayStore that keeps its records in the
// given Redis.
func NewRedisReplayStore(client redis.Cmdable) (*RedisReplayStore, error) {
	if client == nil {
		return nil, errors.New("cgjwt: NewRedisReplayStore: redis client required")
	}
	return &RedisReplayStore{client: client}, nil
}

// Admit writes the pair with SET NX and the given expiry. Redis runs the
// command atomically, so exactly one of many concurrent callers gets true.
func (s *RedisReplayStore) Admit(ctx context.Context, kid, jti string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, errors.New("cgjwt: replay record needs a positive ttl")
	}
	err := s.client.SetArgs(ctx, replayKey(kid, jti), "1", redis.SetArgs{Mode: "NX", TTL: ttl}).Err()
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, redis.Nil):
		// SET NX answers nil when the key exists: the token is a replay.
		return false, nil
	default:
		return false, fmt.Errorf("redis SET NX: %w", err)
	}
}

var (
	componentReplayedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_component_replay_rejected_total",
		Help: "Component CG-JWTs rejected because their (kid, jti) was already in the replay store.",
	})
	componentReplayStateUnavailableTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_component_replay_state_unavailable_total",
		Help: "Component CG-JWTs refused because the replay store did not answer. These calls fail closed.",
	})
)
