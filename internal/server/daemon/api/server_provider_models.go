// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_provider_models.go
//
// TestProvider, ListProviderModels and GetProviderHealth of a SAVED provider
// (gibson#1394, ADR-0172). Each one is one GET of /v1/models through the route
// of the provider on the model gateway. No call tests a credential that is not
// saved, and the daemon builds no provider client and holds no credential for
// these calls. The wizard saves the provider first and tests it after.
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
	"github.com/zeroroot-ai/sdk/auth"
)

// providerListTimeout bounds one model list call, so a hung provider does not pin
// the handler.
const providerListTimeout = 15 * time.Second

// providerRouteWait bounds the wait of a provider test for the route of a new
// provider. The tenant operator renders the route from a pull of the provider
// records every 30 seconds, and the render takes some seconds more. A user saves
// a provider and tests it by name at once (dashboard#372), so the test waits for
// the route instead of showing "route not found".
const (
	providerRouteWait     = 45 * time.Second
	providerRouteInterval = time.Second
)

// providerListCacheTTL is how long a successful list stays valid for one
// provider of one tenant.
const providerListCacheTTL = 5 * time.Minute

// modelLister is the part of the model client that the model list handlers use.
type modelLister interface {
	Models(ctx context.Context, caller modelclient.Caller, target modelclient.Target) ([]modelclient.ModelEntry, error)
}

// WithModelLister wires the model client for the model list handlers.
func (s *DaemonServer) WithModelLister(l modelLister) *DaemonServer {
	s.modelLister = l
	return s
}

// providerListCache keeps the last good model list of each provider of each
// tenant. A call that fails does not replace it, and it is not served as the
// answer of a failed call: a test must show the state of the provider now.
type providerListCache struct {
	mu      sync.Mutex
	entries map[string]cachedList
	now     func() time.Time
}

type cachedList struct {
	models []modelclient.ModelEntry
	at     time.Time
}

func newProviderListCache() *providerListCache {
	return &providerListCache{entries: map[string]cachedList{}, now: time.Now}
}

func (c *providerListCache) get(tenant, provider string) ([]modelclient.ModelEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[tenant+"/"+provider]
	if !ok || c.now().Sub(e.at) > providerListCacheTTL {
		return nil, false
	}
	return e.models, true
}

func (c *providerListCache) put(tenant, provider string, models []modelclient.ModelEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[tenant+"/"+provider] = cachedList{models: models, at: c.now()}
}

func (c *providerListCache) drop(tenant, provider string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, tenant+"/"+provider)
}

// listSavedProvider checks that the provider is saved, and sends one model list
// call through its route. purpose is model_list or provider_probe. The user of
// the request is the initiator of the grant.
func (s *DaemonServer) listSavedProvider(
	ctx context.Context, tenantID, name, purpose string,
) ([]modelclient.ModelEntry, int64, error) {
	if s.providerConfig == nil {
		return nil, 0, status_grpc.Errorf(codes.FailedPrecondition,
			"daemon `security.key_provider` not configured — provider storage is disabled")
	}
	if s.modelLister == nil {
		return nil, 0, status_grpc.Errorf(codes.FailedPrecondition, "the model gateway client is not configured")
	}
	if _, err := s.providerConfig.Get(ctx, tenantID, name); err != nil {
		return nil, 0, toGRPCProviderError("get provider", err)
	}
	initiator, err := callerInitiator(ctx)
	if err != nil {
		return nil, 0, err
	}
	list := func() ([]modelclient.ModelEntry, error) {
		callCtx, cancel := context.WithTimeout(ctx, providerListTimeout)
		defer cancel()
		return s.modelLister.Models(callCtx,
			modelclient.Caller{Tenant: tenantID, Purpose: purpose, Initiator: initiator},
			modelclient.Target{Tenant: tenantID, Provider: name})
	}
	start := time.Now()
	var models []modelclient.ModelEntry
	if purpose == modelcall.PurposeProviderProbe {
		// A test follows a save. Only a test waits for the route. The health poll
		// and the list read the state now and do not wait.
		wait, interval := s.routeWait, s.routeInterval
		if wait <= 0 {
			wait = providerRouteWait
		}
		if interval <= 0 {
			interval = providerRouteInterval
		}
		models, err = waitForRoute(ctx, wait, interval, list)
	} else {
		models, err = list()
	}
	return models, time.Since(start).Milliseconds(), err
}

// waitForRoute calls list again while the gateway answers "no route" (404). Any
// other result returns at once. When the deadline passes it returns the last
// error with the time that it waited, so the user sees that the route did not
// appear, and not only a 404.
func waitForRoute(
	ctx context.Context, deadline, interval time.Duration, list func() ([]modelclient.ModelEntry, error),
) ([]modelclient.ModelEntry, error) {
	timeout := time.NewTimer(deadline)
	defer timeout.Stop()
	for {
		models, err := list()
		var api *modelclient.APIError
		if err == nil || !errors.As(err, &api) || !api.NoRoute() {
			return models, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for the route of the provider: %w", ctx.Err())
		case <-timeout.C:
			return nil, fmt.Errorf("the route of the provider did not appear within %s: %w", deadline, err)
		case <-time.After(interval):
		}
	}
}

// gatewayErrorClass maps an error of the gateway to the error class of the
// dashboard. A 404 means that the route does not exist yet.
func gatewayErrorClass(err error) string {
	var api *modelclient.APIError
	if errors.As(err, &api) {
		switch {
		case api.Refused():
			return "auth_failed"
		case api.NoRoute():
			return "route_not_ready"
		case api.Status == http.StatusTooManyRequests:
			return "rate_limited"
		}
	}
	return classifyProviderError(err)
}

// gatewayErrorMessage is the text for the user. It holds no header and no
// credential. The body of the provider is short and comes from the provider.
func gatewayErrorMessage(err error) string {
	var api *modelclient.APIError
	if errors.As(err, &api) {
		switch {
		case api.NoRoute():
			return "the route of the provider is not ready yet: wait a moment and test again"
		case api.Refused():
			return "the gateway or the provider refused the call: check the credential and the model access"
		}
		return "the provider answered " + http.StatusText(api.Status) + ": " + api.Body
	}
	return err.Error()
}

func modelEntriesToProto(models []modelclient.ModelEntry) []*tenantv1.ModelDescriptor {
	out := make([]*tenantv1.ModelDescriptor, 0, len(models))
	for _, m := range models {
		out = append(out, &tenantv1.ModelDescriptor{
			Name:          m.ID,
			ContextWindow: int32(m.ContextWindow), //nolint:gosec // model context windows are at most ~10M
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// TestProvider tests a saved provider: one GET of the model list through its
// route. It reads no cache, so the answer is the state of the provider now. A
// good answer fills the cache of ListProviderModels.
func (s *DaemonServer) TestProvider(ctx context.Context, req *tenantv1.TestProviderRequest) (*tenantv1.TestProviderResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	if req.GetName() == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "name is required")
	}
	models, latency, err := s.listSavedProvider(ctx, tenantID, req.GetName(), modelcall.PurposeProviderProbe)
	var rpcErr interface{ GRPCStatus() *status_grpc.Status }
	if errors.As(err, &rpcErr) {
		return nil, err
	}
	if err != nil {
		return &tenantv1.TestProviderResponse{LatencyMs: latency, Error: gatewayErrorMessage(err)}, nil
	}
	s.listCache().put(tenantID, req.GetName(), models)
	resp := &tenantv1.TestProviderResponse{Ok: true, LatencyMs: latency, Models: modelEntriesToProto(models)}
	if rec, gerr := s.providerConfig.Get(ctx, tenantID, req.GetName()); gerr == nil && rec != nil {
		resp.Model = rec.DefaultModel
	}
	return resp, nil
}

// ListProviderModels returns the models of a saved provider. A list that is
// fresh in the cache is served from it. A failed call returns the error and
// changes nothing.
func (s *DaemonServer) ListProviderModels(ctx context.Context, req *tenantv1.ListProviderModelsRequest) (*tenantv1.ListProviderModelsResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	name := req.GetName()
	if name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "name is required")
	}
	if cached, ok := s.listCache().get(tenantID, name); ok {
		return &tenantv1.ListProviderModelsResponse{Ok: true, Models: modelEntriesToProto(cached)}, nil
	}
	models, latency, err := s.listSavedProvider(ctx, tenantID, name, modelcall.PurposeModelList)
	var rpcErr interface{ GRPCStatus() *status_grpc.Status }
	if errors.As(err, &rpcErr) {
		return nil, err
	}
	if err != nil {
		return &tenantv1.ListProviderModelsResponse{
			Ok: false, ErrorMessage: gatewayErrorMessage(err), ErrorClass: gatewayErrorClass(err), LatencyMs: latency,
		}, nil
	}
	s.listCache().put(tenantID, name, models)
	return &tenantv1.ListProviderModelsResponse{Ok: true, Models: modelEntriesToProto(models), LatencyMs: latency}, nil
}

// GetProviderHealth reports whether the model list of a saved provider answers.
func (s *DaemonServer) GetProviderHealth(ctx context.Context, req *tenantv1.GetProviderHealthRequest) (*tenantv1.GetProviderHealthResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "tenant context required")
	}
	_, _, err := s.listSavedProvider(ctx, tenantID, req.GetName(), modelcall.PurposeModelList)
	checkedAt := time.Now().UTC().Format(time.RFC3339)
	var rpcErr interface{ GRPCStatus() *status_grpc.Status }
	if errors.As(err, &rpcErr) {
		return nil, err
	}
	if err != nil {
		return &tenantv1.GetProviderHealthResponse{Healthy: false, LastCheckedAt: checkedAt, Error: gatewayErrorMessage(err)}, nil
	}
	return &tenantv1.GetProviderHealthResponse{Healthy: true, LastCheckedAt: checkedAt}, nil
}

// listCache returns the list cache of the server.
func (s *DaemonServer) listCache() *providerListCache {
	s.listCacheOnce.Do(func() { s.providerListCache = newProviderListCache() })
	return s.providerListCache
}
