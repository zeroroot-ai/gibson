// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// replayStoreOn returns a replay store on the given Redis. Each call makes a
// new client, as each ext-authz replica has its own.
func replayStoreOn(t *testing.T, mr *miniredis.Miniredis) *RedisReplayStore {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store, err := NewRedisReplayStore(client)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// newTestReplayStore returns a replay store on a Redis of its own.
func newTestReplayStore(t *testing.T) *RedisReplayStore {
	t.Helper()
	return replayStoreOn(t, miniredis.RunT(t))
}

func mustAdmit(t *testing.T, s ReplayStore, kid, jti string, ttl time.Duration) bool {
	t.Helper()
	first, err := s.Admit(context.Background(), kid, jti, ttl)
	if err != nil {
		t.Fatalf("Admit(%s, %s): %v", kid, jti, err)
	}
	return first
}

func TestNewRedisReplayStore_RequiresClient(t *testing.T) {
	if _, err := NewRedisReplayStore(nil); err == nil {
		t.Fatal("a nil client must be an error")
	}
}

func TestRedisReplayStore_AdmitsOnceThenRefuses(t *testing.T) {
	s := newTestReplayStore(t)
	if !mustAdmit(t, s, "kid-1", "jti-1", time.Minute) {
		t.Fatal("first admit must succeed")
	}
	if mustAdmit(t, s, "kid-1", "jti-1", time.Minute) {
		t.Fatal("second admit of the same (kid, jti) must be refused")
	}
}

// A second replica, with its own client on the same Redis, refuses the pair
// that the first replica accepted.
func TestRedisReplayStore_SecondReplicaRefuses(t *testing.T) {
	mr := miniredis.RunT(t)
	a, b := replayStoreOn(t, mr), replayStoreOn(t, mr)
	if !mustAdmit(t, a, "kid-1", "jti-1", time.Minute) {
		t.Fatal("replica A must admit the first presentation")
	}
	if mustAdmit(t, b, "kid-1", "jti-1", time.Minute) {
		t.Fatal("replica B must refuse the pair that replica A accepted")
	}
}

// The record expires with the token. After that the expiry check refuses
// the token, so the record has no more value.
func TestRedisReplayStore_RecordExpiresWithTheToken(t *testing.T) {
	mr := miniredis.RunT(t)
	s := replayStoreOn(t, mr)
	if !mustAdmit(t, s, "kid-1", "jti-1", 30*time.Second) {
		t.Fatal("first admit must succeed")
	}
	if got := mr.TTL(replayKey("kid-1", "jti-1")); got <= 0 || got > 30*time.Second {
		t.Fatalf("record ttl = %v, want it positive and at most 30s", got)
	}
	mr.FastForward(31 * time.Second)
	if mr.Exists(replayKey("kid-1", "jti-1")) {
		t.Fatal("the record must be gone after its ttl")
	}
}

func TestRedisReplayStore_RefusesNoTTL(t *testing.T) {
	s := newTestReplayStore(t)
	if _, err := s.Admit(context.Background(), "kid-1", "jti-1", 0); err == nil {
		t.Fatal("a record with no expiry must be an error")
	}
}

func TestRedisReplayStore_KidNamespacesJTI(t *testing.T) {
	s := newTestReplayStore(t)
	if !mustAdmit(t, s, "kid-a", "same", time.Minute) {
		t.Fatal("kid-a first admit must succeed")
	}
	if !mustAdmit(t, s, "kid-b", "same", time.Minute) {
		t.Fatal("kid-b must not be blocked by the jti of kid-a")
	}
	// The split between kid and jti is unambiguous: ("a:b", "c") and
	// ("a", "b:c") are different pairs.
	if !mustAdmit(t, s, "a:b", "c", time.Minute) {
		t.Fatal("(a:b, c) first admit must succeed")
	}
	if !mustAdmit(t, s, "a", "b:c", time.Minute) {
		t.Fatal("(a, b:c) must not collide with (a:b, c)")
	}
}

func TestRedisReplayStore_ConcurrentAdmitElectsOneWinner(t *testing.T) {
	mr := miniredis.RunT(t)
	const callers = 32
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		s := replayStoreOn(t, mr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			first, err := s.Admit(context.Background(), "kid-1", "contended", time.Minute)
			if err != nil {
				t.Errorf("Admit: %v", err)
				return
			}
			if first {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d callers were admitted, want exactly 1", wins)
	}
}

func TestRedisReplayStore_ErrorWhenRedisIsDown(t *testing.T) {
	mr := miniredis.RunT(t)
	s := replayStoreOn(t, mr)
	mr.Close()
	first, err := s.Admit(context.Background(), "kid-1", "jti-1", time.Minute)
	if err == nil {
		t.Fatal("a Redis that does not answer must be an error")
	}
	if first {
		t.Fatal("no answer must never report a first presentation")
	}
}

// twoVerifiers returns two verifiers, as two ext-authz replicas, that share
// one Redis. It also returns the Redis and the signing key.
func twoVerifiers(t *testing.T) (a, b *ComponentVerifier, mr *miniredis.Miniredis, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv := mustGenKey(t)
	srv := startDescriptorServer(t, pub, "agent-1", "agent_principal:9", "acme", "active")
	mr = miniredis.RunT(t)
	build := func() *ComponentVerifier {
		v, err := NewComponentVerifier(ComponentConfig{
			KeysBaseURL:       srv.URL + "/capabilitygrant/v1/keys",
			TTL:               time.Minute,
			ExpectedAudiences: []string{testAudience},
			HTTPClient:        &http.Client{Timeout: 5 * time.Second},
			ReplayStore:       replayStoreOn(t, mr),
		})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	return build(), build(), mr, priv
}

// TestComponentVerify_SecondInstanceRefusesReplay: two verifier instances
// and one Redis. The second instance refuses a token that the first
// accepted.
func TestComponentVerify_SecondInstanceRefusesReplay(t *testing.T) {
	a, b, mr, priv := twoVerifiers(t)
	tok := mintAgentJWT(t, priv, "agent-1", "agent+jwt", time.Now().Add(55*time.Second))

	if _, err := a.Verify(context.Background(), tok, testMethod); err != nil {
		t.Fatalf("first instance: %v", err)
	}
	if _, err := b.Verify(context.Background(), tok, testMethod); !errors.Is(err, ErrReplayed) {
		t.Fatalf("second instance err = %v, want ErrReplayed", err)
	}
	// The record does not outlive the token.
	keys := mr.Keys()
	if len(keys) != 1 {
		t.Fatalf("redis holds %d keys, want 1: %v", len(keys), keys)
	}
	if ttl := mr.TTL(keys[0]); ttl <= 0 || ttl > 55*time.Second {
		t.Fatalf("record ttl = %v, want it positive and at most the token life of 55s", ttl)
	}
}

// TestComponentVerify_RefusesWhenRedisIsDown: when Redis does not answer, a
// token that is valid in each other respect is refused.
func TestComponentVerify_RefusesWhenRedisIsDown(t *testing.T) {
	a, _, mr, priv := twoVerifiers(t)
	// Resolve the descriptor first, so the only failure is the replay store.
	mint := func() string {
		return mintAgentJWT(t, priv, "agent-1", "agent+jwt", time.Now().Add(55*time.Second))
	}
	if _, err := a.Verify(context.Background(), mint(), testMethod); err != nil {
		t.Fatalf("with Redis up: %v", err)
	}
	mr.Close()
	_, err := a.Verify(context.Background(), mint(), testMethod)
	if !errors.Is(err, ErrReplayStateUnavailable) {
		t.Fatalf("with Redis down err = %v, want ErrReplayStateUnavailable", err)
	}
}

// TestNewComponentVerifier_RequiresReplayStore: a verifier with no replay
// store is not a constructible state.
func TestNewComponentVerifier_RequiresReplayStore(t *testing.T) {
	_, err := NewComponentVerifier(ComponentConfig{
		KeysBaseURL:       "https://daemon/capabilitygrant/v1/keys",
		ExpectedAudiences: []string{testAudience},
		HTTPClient:        &http.Client{Timeout: 5 * time.Second},
	})
	if err == nil {
		t.Fatal("NewComponentVerifier accepted a missing replay store")
	}
}
