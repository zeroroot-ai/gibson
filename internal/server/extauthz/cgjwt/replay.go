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

// SetIfAbsenter is the one Redis operation that the replay store needs: an
// atomic write of a key that does not exist, with an expiry. It reports
// whether this call wrote the key. *state.StateClient implements it.
type SetIfAbsenter interface {
	SetIfAbsent(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
}

// RedisReplayStore is the ReplayStore on Redis.
type RedisReplayStore struct {
	client SetIfAbsenter
}

// NewRedisReplayStore returns a ReplayStore that keeps its records in the
// given Redis. client must not be nil.
func NewRedisReplayStore(client SetIfAbsenter) *RedisReplayStore {
	return &RedisReplayStore{client: client}
}

// Admit writes the pair with one atomic set-if-absent call and the given
// expiry, so exactly one of many concurrent callers gets true.
func (s *RedisReplayStore) Admit(ctx context.Context, kid, jti string, ttl time.Duration) (bool, error) {
	first, err := s.client.SetIfAbsent(ctx, replayKey(kid, jti), "1", ttl)
	if err != nil {
		return false, fmt.Errorf("replay record: %w", err)
	}
	return first, nil
}

// replayTTL returns how long the replay record of a token must live: the
// time that the token has left. It reports false when the token has no time
// left, which means that the token is expired.
func replayTTL(exp, now time.Time) (time.Duration, bool) {
	ttl := exp.Sub(now)
	return ttl, ttl > 0
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
