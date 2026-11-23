// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// RunCatalogMission refuses before it creates anything: a call with no tenant, a
// mission that does not render, and a target that is not an id.
func TestRunCatalogMission_RefusesBeforeItCreatesAMission(t *testing.T) {
	d := &daemonImpl{}
	good := map[string]string{"repositoryUrl": "https://github.com/acme/shop", "application": "acme/shop", "forgeConnector": "github-fixloop"}

	_, err := d.RunCatalogMission(context.Background(), api.RunCatalogMissionData{Name: "scan", Params: good, TargetID: "t"})
	require.Error(t, err, "a call with no tenant must be refused")

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	_, err = d.RunCatalogMission(ctx, api.RunCatalogMissionData{Name: "scan", Params: map[string]string{"application": "acme/shop"}, TargetID: "t"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a scan with no branch does not render")

	_, err = d.RunCatalogMission(ctx, api.RunCatalogMissionData{Name: "scan", Params: good, TargetID: "not-an-id"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a target that is not an id is refused")
}
