// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/sdk/auth"
)

// capturingRegistry keeps the ComponentInfo of the last Register call.
type capturingRegistry struct {
	noopRegistry
	got ComponentInfo
}

func (r *capturingRegistry) Register(_ context.Context, _, _, _ string, info ComponentInfo) (string, error) {
	r.got = info
	return "instance-1", nil
}

// TestRegisterComponent_DropsDaemonOwnedMetadata is the failing fixture for
// the rule that a check-in cannot set the keys only the daemon may set. The
// caller sends an address to dial and the name of another user. Neither
// reaches the registry. A key the caller may set stays, and the request map
// is not changed.
func TestRegisterComponent_DropsDaemonOwnedMetadata(t *testing.T) {
	reg := &capturingRegistry{}
	svc := NewComponentServiceServer(reg, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil)

	req := minimalRegisterReq("tool", "my-tool")
	req.Metadata = map[string]string{
		"grpc_endpoint":              "attacker.example:443",
		ComponentMetadataOwnerUserID: "another-user",
		"plugin:host_id":             "host-1",
	}
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	_, err := svc.RegisterComponent(ctx, req)
	require.NoError(t, err)

	assert.NotContains(t, reg.got.Metadata, "grpc_endpoint")
	assert.NotContains(t, reg.got.Metadata, ComponentMetadataOwnerUserID)
	assert.Equal(t, "host-1", reg.got.Metadata["plugin:host_id"])
	assert.Equal(t, "attacker.example:443", req.Metadata["grpc_endpoint"], "the request map must not change")
}

func TestCheckInMetadata_NeverNil(t *testing.T) {
	assert.NotNil(t, checkInMetadata(nil))
}
