// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The validation in Start runs before the listener opens and never reads the
// source, so a zero source stands in for a wired one.
func wiredCallbackServer(td spiffeid.TrustDomain, peers ...spiffeid.ID) *CallbackServer {
	s := NewCallbackServerWithRegistry(slog.Default(), 0, NewCallbackHarnessRegistry(), testEventBus())
	s.SetSPIFFE(&workloadapi.X509Source{}, td, peers)
	return s
}

// The callback server refuses to start with SPIFFE and no trust domain.
func TestCallbackServer_StartRefusesAnEmptyTrustDomain(t *testing.T) {
	envoy := spiffeid.RequireFromString(callbackEnvoySVID(callbackTestTD))
	err := wiredCallbackServer(spiffeid.TrustDomain{}, envoy).Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no trust domain")
}

// A configured peer of a different trust domain has no policy, so the server
// refuses to start and names the peer.
func TestCallbackServer_StartRefusesAPeerOfAnotherTrustDomain(t *testing.T) {
	other := spiffeid.RequireFromString("spiffe://zeroroot.ai/platform/envoy")
	err := wiredCallbackServer(callbackTestTD, other).Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), other.String())
}

// The manager records the trust domain and hands it to its server, both at
// construction and through SetSPIFFE.
func TestCallbackManager_CarriesTheTrustDomain(t *testing.T) {
	envoy := spiffeid.RequireFromString(callbackEnvoySVID(callbackTestTD))
	m := NewCallbackManager(CallbackConfig{
		ServiceOptions: []CallbackServiceOption{testEventBus()},
		ListenAddress:  "127.0.0.1:0",
		X509Source:     &workloadapi.X509Source{},
		TrustDomain:    callbackTestTD,
		PeerSVIDs:      []spiffeid.ID{envoy},
	}, slog.Default())
	assert.Equal(t, callbackTestTD, m.server.trustDomain)

	other := spiffeid.RequireTrustDomainFromString("other.example")
	m.SetSPIFFE(&workloadapi.X509Source{}, other, []spiffeid.ID{envoy})
	assert.Equal(t, other, m.config.TrustDomain)
	assert.Equal(t, other, m.server.trustDomain)
	assert.True(t, m.config.SPIFFEEnabled)
}

// The callback server refuses to start with no fork ledger (D74).
func TestCallbackServer_StartRefusesNoForkLedger(t *testing.T) {
	s := NewCallbackServerWithRegistry(slog.Default(), 0, NewCallbackHarnessRegistry(), testEventBus())
	err := s.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fork ledger")
}
