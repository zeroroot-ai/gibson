// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package state

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func setIfAbsentClient(t *testing.T, mr *miniredis.Miniredis) *StateClient {
	t.Helper()
	cfg := DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	c, err := NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestSetIfAbsent_WritesOnceAndExpires: the first call writes the key, a
// second call does not, and the key leaves with its expiry.
func TestSetIfAbsent_WritesOnceAndExpires(t *testing.T) {
	mr := miniredis.RunT(t)
	a, b := setIfAbsentClient(t, mr), setIfAbsentClient(t, mr)
	ctx := context.Background()

	first, err := a.SetIfAbsent(ctx, "k", "1", 30*time.Second)
	if err != nil || !first {
		t.Fatalf("first call: wrote=%v err=%v, want true, nil", first, err)
	}
	// A second client on the same Redis sees the key.
	again, err := b.SetIfAbsent(ctx, "k", "2", 30*time.Second)
	if err != nil || again {
		t.Fatalf("second call: wrote=%v err=%v, want false, nil", again, err)
	}
	if got, _ := mr.Get("k"); got != "1" {
		t.Fatalf("value = %q, the second call must not change it", got)
	}
	if ttl := mr.TTL("k"); ttl <= 0 || ttl > 30*time.Second {
		t.Fatalf("ttl = %v, want it positive and at most 30s", ttl)
	}
	mr.FastForward(31 * time.Second)
	if mr.Exists("k") {
		t.Fatal("the key must be gone after its expiry")
	}
}

// TestSetIfAbsent_RefusesNoExpiry: a key with no expiry would stay for ever.
func TestSetIfAbsent_RefusesNoExpiry(t *testing.T) {
	c := setIfAbsentClient(t, miniredis.RunT(t))
	if _, err := c.SetIfAbsent(context.Background(), "k", "1", 0); err == nil {
		t.Fatal("a ttl of zero must be an error")
	}
}

// TestSetIfAbsent_ConcurrentCallersElectOneWinner: the command is atomic.
func TestSetIfAbsent_ConcurrentCallersElectOneWinner(t *testing.T) {
	c := setIfAbsentClient(t, miniredis.RunT(t))
	const callers = 32
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	start := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			first, err := c.SetIfAbsent(context.Background(), "contended", "1", time.Minute)
			if err != nil {
				t.Errorf("SetIfAbsent: %v", err)
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
		t.Fatalf("%d callers wrote the key, want exactly 1", wins)
	}
}

// TestSetIfAbsent_ErrorWhenRedisIsDown: no answer is an error, never "wrote".
func TestSetIfAbsent_ErrorWhenRedisIsDown(t *testing.T) {
	mr := miniredis.RunT(t)
	c := setIfAbsentClient(t, mr)
	mr.Close()
	first, err := c.SetIfAbsent(context.Background(), "k", "1", time.Minute)
	if err == nil {
		t.Fatal("a Redis that does not answer must be an error")
	}
	if first {
		t.Fatal("no answer must never report a write")
	}
}
