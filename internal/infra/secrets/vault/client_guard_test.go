// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package vault

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/netguard"
)

// countingVaultStub answers the mount-info probe that New performs after the
// token login, and counts how many requests actually arrived. The count is
// what separates "refused at dial time" from "refused after the round-trip":
// a guard that only inspects the response would still leave a hit here.
func countingVaultStub(t *testing.T) (addr string, hits *atomic.Int64) {
	t.Helper()
	hits = &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"kv","options":{"version":"2"}}}`))
	}))
	t.Cleanup(srv.Close)
	// httptest listens on 127.0.0.1 — loopback, one of the classes the guard
	// refuses. That is the point: the same address is reachable through New
	// and unreachable through NewGuarded.
	return srv.URL, hits
}

func staticTokenConfig(addr string) Config {
	return Config{
		Address: addr,
		Auth:    AuthConfig{Method: AuthMethodToken, Token: "test-token"},
	}
}

func TestNewGuardedRefusesBlockedAddressBeforeConnecting(t *testing.T) {
	addr, hits := countingVaultStub(t)

	_, err := NewGuarded(context.Background(), staticTokenConfig(addr))

	require.Error(t, err, "NewGuarded must refuse a loopback address")
	var blocked *netguard.BlockedAddressError
	require.ErrorAs(t, err, &blocked, "refusal must come from the egress guard, not from a later parse failure")
	require.Equal(t, "loopback", blocked.Class)
	require.Zero(t, hits.Load(), "the guard must refuse before connect(2); no request may reach the destination")
}

// TestNewReachesTheSameAddress is the control for the test above. If this one
// ever fails the guard test proves nothing, because the address would have
// been unreachable either way.
func TestNewReachesTheSameAddress(t *testing.T) {
	addr, hits := countingVaultStub(t)

	_, err := New(context.Background(), staticTokenConfig(addr))

	require.NoError(t, err)
	require.Positive(t, hits.Load(), "unguarded New must reach the destination")
}

// TestNewGuardedGuardSurvivesConfigRoundTrip pins the property that makes the
// guard a control rather than a suggestion: it is not carried by any field a
// caller-supplied or persisted config blob can write.
func TestNewGuardedGuardSurvivesConfigRoundTrip(t *testing.T) {
	addr, hits := countingVaultStub(t)

	// A config that came off the wire cannot have set guardEgress, and
	// cannot clear it either — NewGuarded sets it on its own copy.
	fromBlob := staticTokenConfig(addr)
	require.False(t, fromBlob.guardEgress, "a Config built from wire fields must not carry the guard by itself")

	_, err := NewGuarded(context.Background(), fromBlob)
	require.Error(t, err)
	require.Zero(t, hits.Load())

	var blocked *netguard.BlockedAddressError
	require.ErrorAs(t, err, &blocked)
}

// TestInstallEgressGuardFallsBackWhenTransportIsUnfamiliar covers the branch
// that matters if the Vault api package ever stops handing out a stock
// *http.Transport: losing environment TLS tuning is acceptable, silently
// losing the guard is not.
func TestInstallEgressGuardFallsBackWhenTransportIsUnfamiliar(t *testing.T) {
	addr, hits := countingVaultStub(t)

	cfg := api.DefaultConfig()
	cfg.Address = addr
	cfg.HttpClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unreachable: the guarded client should have replaced this transport")
	})}
	installEgressGuard(cfg)

	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	client.SetToken("test-token")

	_, err = client.Logical().ReadWithContext(context.Background(), "sys/internal/ui/mounts/secret")
	require.Error(t, err)
	var blocked *netguard.BlockedAddressError
	require.ErrorAs(t, err, &blocked, "the fallback client must still carry the guard")
	require.Zero(t, hits.Load())
}

// roundTripperFunc is an http.RoundTripper that is deliberately not an
// *http.Transport, to drive the fallback branch above.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
