// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package orgtenant

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock lets tests move time forward deterministically.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// countingHandler serves tenant_id for orgID "mapped" and empty for
// anything else, counting requests it actually serves.
func countingHandler(t *testing.T, hits *int64) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		orgID := r.URL.Path[len("/identity/v1/org-tenant/"):]
		w.Header().Set("Content-Type", "application/json")
		switch orgID {
		case "mapped":
			_, _ = fmt.Fprint(w, `{"tenant_id":"acme"}`)
		default:
			_, _ = fmt.Fprint(w, `{"tenant_id":""}`)
		}
	}
}

func TestTenantForOrg_PositiveHitIsCachedThenRefetched(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(countingHandler(t, &hits))
	t.Cleanup(srv.Close)
	clock := newFakeClock()

	r, err := New(Config{Client: srv.Client(), BaseURL: srv.URL + "/identity/v1/org-tenant/", Now: clock.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 3; i++ {
		tenant, err := r.TenantForOrg(context.Background(), "mapped")
		if err != nil || tenant != "acme" {
			t.Fatalf("TenantForOrg = (%q, %v), want (acme, nil)", tenant, err)
		}
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("hits = %d, want 1 (cached)", got)
	}

	clock.Advance(DefaultPositiveTTL + time.Second)
	if _, err := r.TenantForOrg(context.Background(), "mapped"); err != nil {
		t.Fatalf("TenantForOrg after TTL: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Fatalf("hits after TTL expiry = %d, want 2 (refetched)", got)
	}
}

func TestTenantForOrg_UnmappedIsCachedOnlyForNegativeTTL(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(countingHandler(t, &hits))
	t.Cleanup(srv.Close)
	clock := newFakeClock()

	r, err := New(Config{Client: srv.Client(), BaseURL: srv.URL + "/identity/v1/org-tenant/", Now: clock.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = r.TenantForOrg(context.Background(), "999")
	if !errors.Is(err, ErrNoTenant) {
		t.Fatalf("err = %v, want ErrNoTenant", err)
	}
	if _, err := r.TenantForOrg(context.Background(), "999"); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("second call err = %v, want ErrNoTenant (cached)", err)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("hits = %d, want 1 (cached within negative TTL)", got)
	}

	clock.Advance(DefaultNegativeTTL + time.Second)
	if _, err := r.TenantForOrg(context.Background(), "999"); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("err after negative TTL = %v, want ErrNoTenant", err)
	}
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Fatalf("hits after negative TTL expiry = %d, want 2 (refetched)", got)
	}
}

func TestTenantForOrg_TransportAndStatusErrorsAreNeverCached(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	r, err := New(Config{Client: srv.Client(), BaseURL: srv.URL + "/identity/v1/org-tenant/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 3; i++ {
		_, err := r.TenantForOrg(context.Background(), "123")
		if err == nil || errors.Is(err, ErrNoTenant) {
			t.Fatalf("call %d: err = %v, want a non-ErrNoTenant error", i, err)
		}
	}
	if got := atomic.LoadInt64(&hits); got != 3 {
		t.Fatalf("hits = %d, want 3 (every call refetched, nothing cached)", got)
	}
}

func TestTenantForOrg_404IsAnErrorNeverUnmapped(t *testing.T) {
	// A 404 means the route itself is absent (an old daemon) — never
	// "this org has no tenant." Confusing the two would silently strip
	// every user's tenant during a version-skewed rollout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	r, err := New(Config{Client: srv.Client(), BaseURL: srv.URL + "/identity/v1/org-tenant/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.TenantForOrg(context.Background(), "123")
	if err == nil || errors.Is(err, ErrNoTenant) {
		t.Fatalf("err = %v, want a plain error (not ErrNoTenant)", err)
	}
}

func TestTenantForOrg_BadJSONIsAnErrorAndNotCached(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = fmt.Fprint(w, `not json`)
	}))
	t.Cleanup(srv.Close)

	r, err := New(Config{Client: srv.Client(), BaseURL: srv.URL + "/identity/v1/org-tenant/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := r.TenantForOrg(context.Background(), "123"); err == nil {
		t.Fatal("want error for malformed JSON body")
	}
	if _, err := r.TenantForOrg(context.Background(), "123"); err == nil {
		t.Fatal("second call: want error again (not cached)")
	}
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Fatalf("hits = %d, want 2 (bad JSON never cached)", got)
	}
}

func TestTenantForOrg_ConcurrentMissesMakeOneFetch(t *testing.T) {
	var hits int64
	block := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		once.Do(func() { close(started) })
		<-block
		_, _ = fmt.Fprint(w, `{"tenant_id":"acme"}`)
	}))
	t.Cleanup(srv.Close)

	r, err := New(Config{Client: srv.Client(), BaseURL: srv.URL + "/identity/v1/org-tenant/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 10
	var wg sync.WaitGroup
	results := make([]string, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = r.TenantForOrg(context.Background(), "concurrent")
		}(i)
	}
	<-started
	close(block)
	wg.Wait()

	for i := range results {
		if errs[i] != nil || results[i] != "acme" {
			t.Fatalf("goroutine %d: (%q, %v), want (acme, nil)", i, results[i], errs[i])
		}
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("hits = %d, want 1 (singleflight joined concurrent misses)", got)
	}
}

func TestTenantForOrg_MalformedOrgIDMakesNoFetch(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(countingHandler(t, &hits))
	t.Cleanup(srv.Close)

	r, err := New(Config{Client: srv.Client(), BaseURL: srv.URL + "/identity/v1/org-tenant/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, bad := range []string{"", "has spaces", "../../etc/passwd", string(make([]byte, 100))} {
		if _, err := r.TenantForOrg(context.Background(), bad); !errors.Is(err, ErrNoTenant) {
			t.Errorf("TenantForOrg(%q) err = %v, want ErrNoTenant", bad, err)
		}
	}
	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("hits = %d, want 0 (malformed org id never reaches the daemon)", got)
	}
}

func TestTenantForOrg_MapClearsAtMaxSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"tenant_id":"acme"}`)
	}))
	t.Cleanup(srv.Close)

	r, err := New(Config{Client: srv.Client(), BaseURL: srv.URL + "/identity/v1/org-tenant/", MaxSize: 2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, id := range []string{"1", "2"} {
		if _, err := r.TenantForOrg(context.Background(), id); err != nil {
			t.Fatalf("TenantForOrg(%s): %v", id, err)
		}
	}
	if len(r.entries) != 2 {
		t.Fatalf("entries = %d, want 2 before overflow", len(r.entries))
	}
	// A third distinct org triggers the clear-and-reset since the map is
	// already at maxSize when the fetch for "3" completes.
	if _, err := r.TenantForOrg(context.Background(), "3"); err != nil {
		t.Fatalf("TenantForOrg(3): %v", err)
	}
	if len(r.entries) != 1 {
		t.Fatalf("entries after overflow = %d, want 1 (map cleared then re-populated with the new entry)", len(r.entries))
	}
}

func TestNew_RequiresClientAndBaseURL(t *testing.T) {
	if _, err := New(Config{BaseURL: "https://example.test/"}); err == nil {
		t.Fatal("want error with no Client")
	}
	if _, err := New(Config{Client: http.DefaultClient}); err == nil {
		t.Fatal("want error with no BaseURL")
	}
}
