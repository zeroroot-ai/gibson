// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestReplayCache_AdmitsOnceThenRefuses(t *testing.T) {
	c := newReplayCache(16)
	now := time.Now()
	deadline := now.Add(time.Minute)

	if !c.admit("kid-1", "jti-1", deadline, now) {
		t.Fatal("first admit must succeed")
	}
	if c.admit("kid-1", "jti-1", deadline, now) {
		t.Fatal("second admit of the same (kid, jti) must be refused")
	}
}

func TestReplayCache_ForgetsExpiredEntries(t *testing.T) {
	// Past the token's own exp the ordinary expiry check rejects it anyway,
	// so holding the jti costs memory for no benefit. Once forgotten, the
	// pair is admittable again — which is safe precisely because such a
	// token can no longer verify.
	c := newReplayCache(16)
	now := time.Now()
	deadline := now.Add(30 * time.Second)

	if !c.admit("kid-1", "jti-1", deadline, now) {
		t.Fatal("first admit must succeed")
	}
	later := deadline.Add(time.Second)
	if !c.admit("kid-1", "jti-1", later.Add(30*time.Second), later) {
		t.Fatal("an entry past its deadline must no longer block")
	}
}

func TestReplayCache_KidNamespacesJTI(t *testing.T) {
	c := newReplayCache(16)
	now := time.Now()
	deadline := now.Add(time.Minute)

	if !c.admit("kid-a", "same", deadline, now) {
		t.Fatal("kid-a first admit must succeed")
	}
	if !c.admit("kid-b", "same", deadline, now) {
		t.Fatal("kid-b must not be blocked by kid-a's jti")
	}
}

func TestReplayCache_BoundsSize(t *testing.T) {
	// The cache must not grow without limit under load. Capacity eviction
	// degrades the guarantee for the evicted entry, so the bound exists to
	// cap memory, not to be hit routinely.
	const max = 8
	c := newReplayCache(max)
	now := time.Now()
	for i := 0; i < max*10; i++ {
		if !c.admit("kid-1", fmt.Sprintf("jti-%d", i), now.Add(time.Minute), now) {
			t.Fatalf("distinct jti %d must be admitted", i)
		}
	}
	c.mu.Lock()
	size := len(c.entries)
	c.mu.Unlock()
	if size > max {
		t.Fatalf("cache holds %d entries, want at most %d", size, max)
	}
}

func TestReplayCache_ConcurrentAdmitElectsOneWinner(t *testing.T) {
	// ext-authz serves concurrent Check calls; two pods' worth of replayed
	// traffic can land on the same process at once. Exactly one caller may
	// win the same (kid, jti).
	c := newReplayCache(1024)
	now := time.Now()
	deadline := now.Add(time.Minute)

	const goroutines = 32
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if c.admit("kid-1", "contended", deadline, now) {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins != 1 {
		t.Fatalf("%d goroutines were admitted, want exactly 1", wins)
	}
}
