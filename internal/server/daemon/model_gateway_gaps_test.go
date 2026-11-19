// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

func testDaemonMinter(t *testing.T) *capabilitygrant.Minter {
	t.Helper()
	minter, err := capabilitygrant.NewMinter(t.Context(), capabilitygrant.Config{
		Issuer:      "https://api.example.com",
		Audience:    "gibson-daemon",
		KeyProvider: testKeyProvider{key: []byte("0123456789abcdef0123456789abcdef")},
		KeyID:       "cg-test-v1",
	})
	require.NoError(t, err)
	return minter
}

func TestLazyDaemonMinter_NeedsTheSigningKey(t *testing.T) {
	l := lazyDaemonMinter{d: &daemonImpl{}}
	_, err := l.Mint(capabilitygrant.MintRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = l.MintDaemonCall(capabilitygrant.DaemonCallRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestLazyDaemonMinter_SignsWithTheMinterOfTheDaemon(t *testing.T) {
	l := lazyDaemonMinter{d: &daemonImpl{cgMinter: testDaemonMinter(t)}}

	tok, err := l.MintDaemonCall(capabilitygrant.DaemonCallRequest{Tenant: "acme", Purpose: modelcall.PurposeEmbedding})
	require.NoError(t, err)
	assert.Equal(t, modelcall.PurposeEmbedding, modelcall.ClaimString(tok, modelcall.ClaimPurpose))

	// A purpose that is not in the closed set gets no grant, and the error names the step.
	_, err = l.MintDaemonCall(capabilitygrant.DaemonCallRequest{Tenant: "acme", Purpose: "admin"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sign the daemon call grant")

	task, err := l.Mint(capabilitygrant.MintRequest{
		Subject: "component:agent:scout", Tenant: "acme", MissionID: "m1", TaskID: "t1",
		AllowedRPCs: modelcall.GrantRoutes(),
	})
	require.NoError(t, err)
	assert.Equal(t, "acme", modelcall.ClaimString(task, "tenant"))

	_, err = l.Mint(capabilitygrant.MintRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sign the grant of a model call")
}

func TestNewModelClient_NeedsTheGatewayURLAndTheCA(t *testing.T) {
	d := &daemonImpl{}
	t.Setenv(EnvModelGatewayURL, "")
	_, err := d.newModelClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), EnvModelGatewayURL)

	t.Setenv(EnvModelGatewayURL, "https://model.svc.internal")
	t.Setenv(EnvModelGatewayCAFile, "")
	_, err = d.newModelClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), EnvModelGatewayCAFile)

	ca := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(ca, selfSignedPEM(t), 0o600))
	t.Setenv(EnvModelGatewayCAFile, ca)
	c, err := d.newModelClient()
	require.NoError(t, err)
	assert.NotNil(t, c)
}
