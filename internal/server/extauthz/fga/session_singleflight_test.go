// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
)

// gatedFGA answers every Check with allowed=true, but only after release is
// closed, so a test can pile concurrent callers onto one in-flight call.
type gatedFGA struct {
	release chan struct{}
	err     error
	calls   int32
}

func (g *gatedFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	atomic.AddInt32(&g.calls, 1)
	return &gatedReq{g: g}
}

type gatedReq struct{ g *gatedFGA }

func (r *gatedReq) Body(_ fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *gatedReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *gatedReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	<-r.g.release
	if r.g.err != nil {
		return nil, r.g.err
	}
	allowed := true
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &allowed}}, nil
}
func (r *gatedReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *gatedReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *gatedReq) GetContext() context.Context               { return context.Background() }
func (r *gatedReq) GetBody() *fgaclient.ClientCheckRequest    { return nil }
func (r *gatedReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// A dashboard page load fans out several RPCs with one token. The gates that
// are in flight together for that token share one FGA round-trip, so a slow
// OpenFGA costs the breaker one failure per burst, not one per RPC.
func TestCachedChecker_CheckActiveSession_SharesOneInFlightCall(t *testing.T) {
	t.Parallel()
	stub := &gatedFGA{release: make(chan struct{})}
	cc := NewCachedChecker(NewChecker(stub, makeMinimalReg(t)), time.Hour, 100)
	iat := time.Unix(1_700_000_100, 0).UTC()

	const burst = 6
	var wg sync.WaitGroup
	results := make([]bool, burst)
	errs := make([]error, burst)
	for i := range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = cc.CheckActiveSession(context.Background(), "u-1", "acme", iat)
		}()
	}
	waitForCalls(t, &stub.calls, 1)
	waitForCallersInGate(t, burst)
	close(stub.release)
	wg.Wait()

	for i := range burst {
		if errs[i] != nil || !results[i] {
			t.Fatalf("caller %d: ok=%v err=%v", i, results[i], errs[i])
		}
	}
	if got := atomic.LoadInt32(&stub.calls); got != 1 {
		t.Fatalf("a burst of %d gates for one token must reach FGA once, got %d calls", burst, got)
	}
}

// A different token, and the user-scoped gate for the same token, are not
// the same check and never share a call.
func TestCachedChecker_SessionGates_DifferentKeysDoNotShare(t *testing.T) {
	t.Parallel()
	stub := &gatedFGA{release: make(chan struct{})}
	cc := NewCachedChecker(NewChecker(stub, makeMinimalReg(t)), time.Hour, 100)
	iat := time.Unix(1_700_000_100, 0).UTC()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _, _ = cc.CheckActiveSession(context.Background(), "u-1", "acme", iat) }()
	go func() {
		defer wg.Done()
		_, _ = cc.CheckActiveSession(context.Background(), "u-1", "acme", iat.Add(time.Second))
	}()
	go func() { defer wg.Done(); _, _ = cc.CheckUserSession(context.Background(), "u-1", iat) }()
	waitForCalls(t, &stub.calls, 3)
	close(stub.release)
	wg.Wait()

	if got := atomic.LoadInt32(&stub.calls); got != 3 {
		t.Fatalf("three distinct gates must reach FGA three times, got %d", got)
	}
}

// The first caller of a shared call may abort. The call it started must
// still answer the callers that joined it.
func TestCachedChecker_CheckActiveSession_SharedCallSurvivesFirstCallerCancel(t *testing.T) {
	t.Parallel()
	stub := &gatedFGA{release: make(chan struct{})}
	cc := NewCachedChecker(NewChecker(stub, makeMinimalReg(t)), time.Hour, 100)
	iat := time.Unix(1_700_000_100, 0).UTC()

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = cc.CheckActiveSession(firstCtx, "u-1", "acme", iat) }()
	waitForCalls(t, &stub.calls, 1)

	var second bool
	var secondErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		second, secondErr = cc.CheckActiveSession(context.Background(), "u-1", "acme", iat)
	}()
	waitForCallersInGate(t, 2)
	cancelFirst()
	close(stub.release)
	wg.Wait()

	if secondErr != nil || !second {
		t.Fatalf("the joined caller must get the shared allow, got ok=%v err=%v", second, secondErr)
	}
	if got := atomic.LoadInt32(&stub.calls); got != 1 {
		t.Fatalf("expected one shared FGA call, got %d", got)
	}
}

// waitForCallersInGate blocks until want goroutines sit inside
// singleflight.Group.Do: the one running the FGA call and the ones waiting
// to share its result. Without this the test could release the call before
// a joiner arrives, and that joiner would start a call of its own.
// Every caller that shares a failed call gets the failure, so the server maps
// each of them to Unavailable rather than one of them to a silent allow.
func TestCachedChecker_CheckActiveSession_SharedCallSharesTheError(t *testing.T) {
	t.Parallel()
	stub := &gatedFGA{release: make(chan struct{}), err: errors.New("fga: boom")}
	cc := NewCachedChecker(NewChecker(stub, makeMinimalReg(t)), time.Hour, 100)
	iat := time.Unix(1_700_000_100, 0).UTC()

	const burst = 3
	var wg sync.WaitGroup
	errs := make([]error, burst)
	for i := range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = cc.CheckActiveSession(context.Background(), "u-1", "acme", iat)
		}()
	}
	waitForCalls(t, &stub.calls, 1)
	waitForCallersInGate(t, burst)
	close(stub.release)
	wg.Wait()

	for i := range burst {
		if errs[i] == nil || !strings.Contains(errs[i].Error(), "boom") {
			t.Fatalf("caller %d: want the shared FGA error, got %v", i, errs[i])
		}
	}
	if got := atomic.LoadInt32(&stub.calls); got != 1 {
		t.Fatalf("expected one shared FGA call, got %d", got)
	}
}

// waitForCallersInGate blocks until want goroutines OF THIS TEST sit inside
// singleflight.Group.Do: the one running the FGA call and the ones waiting
// to share its result. Without this the test could release the call before
// a joiner arrives, and that joiner would start a call of its own. The
// tests of this file run in parallel, so a goroutine counts only when its
// stack names the calling test: another test's callers in the gate must not
// satisfy the wait (that released a call early under the coverage run).
func waitForCallersInGate(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		got := 0
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "singleflight.(*Group).Do(") && strings.Contains(g, t.Name()) {
				got++
			}
		}
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines in the session gate, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForCalls(t *testing.T, calls *int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(calls) < want {
		if time.Now().After(deadline) {
			t.Fatalf("FGA saw %d calls, want %d", atomic.LoadInt32(calls), want)
		}
		time.Sleep(time.Millisecond)
	}
}
