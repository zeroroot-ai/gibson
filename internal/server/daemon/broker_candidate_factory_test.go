// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/netguard"
	sdkvault "github.com/zeroroot-ai/gibson/internal/infra/secrets/vault"
)

// vaultStub answers the mount-info probe and counts arrivals. The count is the
// assertion that separates a connect-time refusal from a response-time one.
func vaultStub(t *testing.T) (addr string, hits *atomic.Int64) {
	t.Helper()
	hits = &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"kv","options":{"version":"2"}}}`))
	}))
	t.Cleanup(srv.Close)
	// httptest listens on 127.0.0.1 — loopback, a class the guard refuses.
	return srv.URL, hits
}

func candidateBlob(t *testing.T, addr string) []byte {
	t.Helper()
	blob, err := json.Marshal(sdkvault.Config{
		Address: addr,
		Auth:    sdkvault.AuthConfig{Method: sdkvault.AuthMethodToken, Token: "test-token"},
	})
	require.NoError(t, err)
	return blob
}

type recordingWarner struct{ msgs []string }

func (r *recordingWarner) Warn(_ context.Context, msg string, _ ...any) {
	r.msgs = append(r.msgs, msg)
}

// TestBrokerCandidateFactory_RefusesBlockedAddressBeforeConnecting is the
// property the candidate path exists to have. The address in a candidate comes
// from a tenant admin's RPC, and probing it dials it while presenting
// credentials, so a blocked destination must be refused before any packet
// leaves.
func TestBrokerCandidateFactory_RefusesBlockedAddressBeforeConnecting(t *testing.T) {
	addr, hits := vaultStub(t)
	warner := &recordingWarner{}

	factories := newBrokerCandidateFactories(context.Background(), false, warner)
	require.Contains(t, factories, "vault")

	_, err := factories["vault"](candidateBlob(t, addr))

	require.Error(t, err)
	var blocked *netguard.BlockedAddressError
	require.ErrorAs(t, err, &blocked)
	require.Equal(t, "loopback", blocked.Class)
	require.Zero(t, hits.Load(), "no request may reach a blocked destination")
	require.Empty(t, warner.msgs, "the secure default must not warn")
}

// TestBrokerCandidateFactory_OptInReachesPrivateAddresses is both the control
// for the test above — proving the address is reachable when the guard is off,
// so the refusal is the guard's doing — and the check that the opt-in an
// operator would need actually works.
func TestBrokerCandidateFactory_OptInReachesPrivateAddresses(t *testing.T) {
	addr, hits := vaultStub(t)
	warner := &recordingWarner{}

	factories := newBrokerCandidateFactories(context.Background(), true, warner)
	_, err := factories["vault"](candidateBlob(t, addr))

	require.NoError(t, err)
	require.Positive(t, hits.Load())
	require.Len(t, warner.msgs, 1, "widening egress on tenants' behalf must be logged")
	require.Contains(t, warner.msgs[0], "allow_private_broker_endpoints")
}

// TestBrokerCandidateFactory_RejectsMalformedBlob keeps the unmarshal error a
// factory error rather than a nil provider a caller would probe.
func TestBrokerCandidateFactory_RejectsMalformedBlob(t *testing.T) {
	factories := newBrokerCandidateFactories(context.Background(), false, nil)
	broker, err := factories["vault"]([]byte("{not json"))
	require.Error(t, err)
	require.Nil(t, broker)
}
