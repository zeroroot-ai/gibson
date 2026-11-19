// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
	"github.com/zeroroot-ai/sdk/auth"
)

// scriptedLister answers each model list call with the next scripted error. When
// the script is empty it returns the models.
type scriptedLister struct {
	errs    []error
	models  []modelclient.ModelEntry
	calls   int
	callers []modelclient.Caller
}

func (l *scriptedLister) Models(
	_ context.Context, caller modelclient.Caller, _ modelclient.Target,
) ([]modelclient.ModelEntry, error) {
	l.calls++
	l.callers = append(l.callers, caller)
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		if err != nil {
			return nil, err
		}
	}
	return l.models, nil
}

func apiErr(status int) error { return &modelclient.APIError{Status: status, Body: "body"} }

func modelServer(t *testing.T, lister *scriptedLister) *DaemonServer {
	t.Helper()
	store := &mockProviderStore{getOut: fakeProviderRecord("claude")}
	s := serverWithStore(t, store).WithModelLister(lister)
	s.routeWait, s.routeInterval = time.Second, time.Millisecond
	return s
}

func modelCtx() context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: "u1", Tenant: auth.MustNewTenantID("acme")})
}

var twoModels = []modelclient.ModelEntry{{ID: "b-model", ContextWindow: 8}, {ID: "a-model", ContextWindow: 4}}

func TestTestProvider_ListsTheModelsThroughTheRouteAsTheCaller(t *testing.T) {
	lister := &scriptedLister{models: twoModels}
	s := modelServer(t, lister)

	resp, err := s.TestProvider(modelCtx(), &tenantv1.TestProviderRequest{Name: "claude"})
	require.NoError(t, err)
	assert.True(t, resp.GetOk())
	assert.Equal(t, "gpt-4o-mini", resp.GetModel(), "the default model of the record")
	require.Len(t, resp.GetModels(), 2)
	assert.Equal(t, "a-model", resp.GetModels()[0].GetName(), "the list is sorted")
	require.Len(t, lister.callers, 1)
	assert.Equal(t, modelcall.PurposeProviderProbe, lister.callers[0].Purpose)
	assert.Equal(t, "acme", lister.callers[0].Tenant)
	assert.NotEmpty(t, lister.callers[0].Initiator, "the user of the request is the initiator")
}

func TestTestProvider_WaitsForANewRouteThenGivesUp(t *testing.T) {
	lister := &scriptedLister{errs: []error{apiErr(http.StatusNotFound), apiErr(http.StatusNotFound)}, models: twoModels}
	s := modelServer(t, lister)
	resp, err := s.TestProvider(modelCtx(), &tenantv1.TestProviderRequest{Name: "claude"})
	require.NoError(t, err)
	assert.True(t, resp.GetOk(), "the route appeared on the third call")
	assert.Equal(t, 3, lister.calls)

	never := &scriptedLister{errs: []error{apiErr(http.StatusNotFound), apiErr(http.StatusNotFound), apiErr(http.StatusNotFound)}}
	s = modelServer(t, never)
	s.routeWait, s.routeInterval = time.Millisecond, time.Hour
	resp, err = s.TestProvider(modelCtx(), &tenantv1.TestProviderRequest{Name: "claude"})
	require.NoError(t, err)
	assert.False(t, resp.GetOk())
	assert.Contains(t, resp.GetError(), "route of the provider is not ready")
}

func TestWaitForRoute_StopsWithTheContextAndReturnsOtherErrorsAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lister := &scriptedLister{errs: []error{apiErr(http.StatusNotFound)}}
	_, err := waitForRoute(ctx, time.Hour, time.Hour, func() ([]modelclient.ModelEntry, error) {
		return lister.Models(ctx, modelclient.Caller{}, modelclient.Target{})
	})
	require.ErrorIs(t, err, context.Canceled)

	boom := errors.New("boom")
	calls := 0
	_, err = waitForRoute(context.Background(), time.Hour, time.Hour, func() ([]modelclient.ModelEntry, error) {
		calls++
		return nil, boom
	})
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 1, calls, "an error that is not 404 does not wait")
}

func TestTestProvider_ErrorTextNamesNoCredential(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{"refused", apiErr(http.StatusForbidden), "refused the call"},
		{"another status", apiErr(http.StatusBadGateway), "the provider answered Bad Gateway: body"},
		{"not an API error", errors.New("dial tcp: no route"), "dial tcp: no route"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := modelServer(t, &scriptedLister{errs: []error{tt.err}})
			resp, err := s.TestProvider(modelCtx(), &tenantv1.TestProviderRequest{Name: "claude"})
			require.NoError(t, err)
			assert.False(t, resp.GetOk())
			assert.Contains(t, resp.GetError(), tt.contains)
		})
	}
}

func TestListProviderModels_CachesAGoodAnswerAndClassifiesAFailure(t *testing.T) {
	lister := &scriptedLister{models: twoModels}
	s := modelServer(t, lister)
	for range 2 {
		resp, err := s.ListProviderModels(modelCtx(), &tenantv1.ListProviderModelsRequest{Name: "claude"})
		require.NoError(t, err)
		assert.True(t, resp.GetOk())
	}
	assert.Equal(t, 1, lister.calls, "the second list is served from the cache")
	assert.Equal(t, modelcall.PurposeModelList, lister.callers[0].Purpose)

	classes := []struct {
		err  error
		want string
	}{
		{apiErr(http.StatusUnauthorized), "auth_failed"},
		{apiErr(http.StatusNotFound), "route_not_ready"},
		{apiErr(http.StatusTooManyRequests), "rate_limited"},
		{apiErr(http.StatusBadGateway), "unknown"},
		{errors.New("connection refused"), "network"},
	}
	for _, tt := range classes {
		failing := modelServer(t, &scriptedLister{errs: []error{tt.err}})
		resp, err := failing.ListProviderModels(modelCtx(), &tenantv1.ListProviderModelsRequest{Name: "claude"})
		require.NoError(t, err)
		assert.False(t, resp.GetOk())
		assert.Equal(t, tt.want, resp.GetErrorClass(), "error %v", tt.err)
		assert.NotEmpty(t, resp.GetErrorMessage())
	}
}

func TestGetProviderHealth_ReportsTheStateOfTheModelList(t *testing.T) {
	s := modelServer(t, &scriptedLister{models: twoModels})
	resp, err := s.GetProviderHealth(modelCtx(), &tenantv1.GetProviderHealthRequest{Name: "claude"})
	require.NoError(t, err)
	assert.True(t, resp.GetHealthy())
	assert.NotEmpty(t, resp.GetLastCheckedAt())

	sick := modelServer(t, &scriptedLister{errs: []error{apiErr(http.StatusForbidden)}})
	resp, err = sick.GetProviderHealth(modelCtx(), &tenantv1.GetProviderHealthRequest{Name: "claude"})
	require.NoError(t, err)
	assert.False(t, resp.GetHealthy())
	assert.Contains(t, resp.GetError(), "refused the call")
}

func TestProviderModelHandlers_Refusals(t *testing.T) {
	s := modelServer(t, &scriptedLister{})
	_, err := s.TestProvider(modelCtx(), &tenantv1.TestProviderRequest{})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err), "TestProvider with no name")
	_, err = s.ListProviderModels(modelCtx(), &tenantv1.ListProviderModelsRequest{})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err), "ListProviderModels with no name")

	// A caller with a tenant and no subject has no identity for the grant.
	anon := auth.WithIdentity(context.Background(), auth.Identity{Tenant: auth.MustNewTenantID("acme")})
	_, err = s.ListProviderModels(anon, &tenantv1.ListProviderModelsRequest{Name: "claude"})
	assert.Equal(t, codes.Unauthenticated, grpcCode(err))

	noLister := serverWithStore(t, &mockProviderStore{getOut: fakeProviderRecord("claude")})
	_, err = noLister.ListProviderModels(modelCtx(), &tenantv1.ListProviderModelsRequest{Name: "claude"})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))

	missing := serverWithStore(t, &mockProviderStore{getErr: fmt.Errorf("get: %w", providerconfig.ErrNotFound)}).
		WithModelLister(&scriptedLister{})
	_, err = missing.ListProviderModels(modelCtx(), &tenantv1.ListProviderModelsRequest{Name: "claude"})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}
