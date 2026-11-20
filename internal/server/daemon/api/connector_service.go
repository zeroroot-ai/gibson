// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantconnector"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/sdk/auth"
)

// CatalogGate is the narrow authorizer slice the connector service needs for
// the platform catalog gate (ADR-0067, closing the ADR-0114 TODO): is a
// catalog entry platform_enabled? The full authz.Authorizer satisfies it.
type CatalogGate interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error)
}

// systemTenantRef is the singleton platform publisher — the only subject the
// model admits for `component.platform_enabled`.
const systemTenantRef = "system_tenant:_system"

// ConnectorStore holds the connectors each tenant enabled (gibson#662).
// *tenantconnector.Store satisfies it.
type ConnectorStore interface {
	Enable(ctx context.Context, tenantID, connectorID string, cfg tenantconnector.Config) (tenantconnector.Connector, error)
	Disable(ctx context.Context, tenantID, connectorID string) error
	List(ctx context.Context, tenantID string) ([]tenantconnector.Connector, error)
}

// ConnectorService is the daemon API a person drives to enable and manage
// third-party MCP connectors (ADR-0114). It serves the connector lifecycle:
// catalog, enable, list, disable. The RPC is the source of truth; the gibson
// CLI and the dashboard are thin clients of it.
//
// The service records what a tenant wants in the platform database and makes
// no Kubernetes call (ADR-0023, gibson#662). The connector operator pulls the
// desired connectors from the daemon, makes each ConnectorInstance, and
// reports its state back, which ListConnectors shows.
type ConnectorService struct {
	tenantv1.UnimplementedConnectorServiceServer

	store ConnectorStore

	// gate answers the platform catalog gate: an entry without its
	// platform_enabled tuple is invisible to ListCatalog and refused by
	// EnableConnector. Required — the service is not registered without it.
	gate CatalogGate
}

// NewConnectorService constructs the service over the given store and
// catalog gate.
func NewConnectorService(store ConnectorStore, gate CatalogGate) *ConnectorService {
	return &ConnectorService{store: store, gate: gate}
}

// callerTenant resolves the caller's tenant from the ext-authz context, and
// only from there.
func (s *ConnectorService) callerTenant(ctx context.Context, rpc string) (string, error) {
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return "", status_grpc.Errorf(codes.PermissionDenied, "%s: missing tenant in context", rpc)
	}
	return tenantID.String(), nil
}

// ListCatalog returns the curated connectors the tenant may enable.
func (s *ConnectorService) ListCatalog(
	ctx context.Context, _ *tenantv1.ListCatalogRequest,
) (*tenantv1.ListCatalogResponse, error) {
	// A caller must be a tenant member; ext-authz enforces the RPC annotation,
	// so the presence of a tenant in the context is the gate here.
	if _, err := s.callerTenant(ctx, "ListCatalog"); err != nil {
		return nil, err
	}
	entries := componentcatalog.ListConnectors()
	// The platform catalog gate (ADR-0067): an entry is visible iff its
	// component object carries platform_enabled from the system tenant. The
	// seeder converges the tuples from this same embedded table, so on a
	// healthy install every entry passes; a de-listed entry disappears here
	// and is refused by EnableConnector. Fail closed on a gate error.
	checks := make([]authz.CheckRequest, len(entries))
	for i, e := range entries {
		checks[i] = authz.CheckRequest{
			User:     systemTenantRef,
			Relation: "platform_enabled",
			Object:   authz.ConnectorComponentObject(e.ID),
		}
	}
	allowed, err := s.gate.BatchCheck(ctx, checks)
	if err != nil || len(allowed) != len(entries) {
		return nil, status_grpc.Errorf(codes.Internal, "ListCatalog: catalog gate: %v", err)
	}
	out := make([]*tenantv1.CatalogEntry, 0, len(entries))
	for i, e := range entries {
		if !allowed[i] {
			continue
		}
		out = append(out, &tenantv1.CatalogEntry{
			Id:                 e.ID,
			DisplayName:        e.DisplayName,
			Description:        e.Description,
			Shape:              string(e.Shape),
			Auth:               string(e.Auth),
			DefaultInstanceUrl: e.DefaultInstanceURL,
			ToolClass:          e.Class,
			EndpointPatterns:   e.EndpointPatterns,
			OauthClient:        e.OAuthClient,
			Variables:          catalogVariables(e),
		})
	}
	return &tenantv1.ListCatalogResponse{Entries: out}, nil
}

// EnableConnector records that the caller's tenant wants the catalog entry.
// The connector operator makes the ConnectorInstance on its next pass. An
// OAuth connector comes up AuthorizationRequired until a human authorizes it.
func (s *ConnectorService) EnableConnector(
	ctx context.Context, req *tenantv1.EnableConnectorRequest,
) (*tenantv1.EnableConnectorResponse, error) {
	tenant, err := s.callerTenant(ctx, "EnableConnector")
	if err != nil {
		return nil, err
	}
	entry, err := componentcatalog.LookupConnector(req.GetCatalogId())
	if err != nil {
		return nil, status_grpc.Errorf(codes.NotFound, "EnableConnector: %v", err)
	}
	// The platform catalog gate: a de-listed entry reads as not-in-catalog,
	// matching its invisibility in ListCatalog. Fail closed on a gate error.
	allowed, err := s.gate.Check(ctx, systemTenantRef, "platform_enabled",
		authz.ConnectorComponentObject(entry.ID))
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "EnableConnector: catalog gate: %v", err)
	}
	if !allowed {
		return nil, status_grpc.Errorf(codes.NotFound,
			"EnableConnector: connector %q is not in the catalog", entry.ID)
	}
	cfg, err := tenantChoice(entry, req)
	if err != nil {
		return nil, err
	}
	c, err := s.store.Enable(ctx, tenant, entry.ID, cfg)
	if err != nil {
		if errors.Is(err, tenantconnector.ErrAlreadyEnabled) {
			return nil, status_grpc.Errorf(codes.AlreadyExists,
				"EnableConnector: connector %q is already enabled", entry.ID)
		}
		return nil, status_grpc.Errorf(codes.Internal, "EnableConnector: %v", err)
	}
	return &tenantv1.EnableConnectorResponse{Connector: c.ConnectorID, Phase: c.Phase}, nil
}

// catalogVariables lists the variables that a tenant gives for an entry.
func catalogVariables(e componentcatalog.ConnectorEntry) []*tenantv1.CatalogVariable {
	out := make([]*tenantv1.CatalogVariable, 0, len(e.Variables))
	for _, v := range e.Variables {
		out = append(out, &tenantv1.CatalogVariable{Name: v.Name, Kind: v.Kind, Patterns: v.Patterns})
	}
	return out
}

// tenantChoice checks what the tenant chose against the catalog entry, and
// returns what the store keeps. A tenant endpoint must match a pattern of the
// entry (gibson#1534). A tenant OAuth client is required for an entry that has
// no dynamic client registration, and refused for any other (gibson#1538).
func tenantChoice(entry componentcatalog.ConnectorEntry, req *tenantv1.EnableConnectorRequest) (tenantconnector.Config, error) {
	var cfg tenantconnector.Config
	if req.GetEndpoint() != "" {
		res, err := entry.ResolveEndpoint(req.GetEndpoint())
		if err != nil {
			return cfg, status_grpc.Errorf(codes.InvalidArgument, "EnableConnector: %v", err)
		}
		cfg.Endpoint = res.Endpoint
	} else if entry.Shape == connectorv1alpha1.ConnectorShapeRemote && entry.Endpoint == "" {
		return cfg, status_grpc.Errorf(codes.InvalidArgument,
			"EnableConnector: connector %q needs an endpoint that matches %v", entry.ID, entry.EndpointPatterns)
	}
	if len(entry.Variables) > 0 || len(req.GetVariables()) > 0 {
		// A value that the entry does not declare, or a missing one, is an
		// error. The check also refuses a private or cluster host (gibson#1508).
		if _, err := entry.ResolveVariables(req.GetVariables()); err != nil {
			return cfg, status_grpc.Errorf(codes.InvalidArgument, "EnableConnector: %v", err)
		}
		cfg.Variables = req.GetVariables()
	}
	id, name := req.GetOauthClientId(), req.GetOauthClientSecretName()
	switch {
	case entry.OAuthClient == componentcatalog.OAuthClientTenant:
		if id == "" || name == "" {
			return cfg, status_grpc.Errorf(codes.InvalidArgument,
				"EnableConnector: connector %q needs oauth_client_id and oauth_client_secret_name: "+
					"the vendor has no dynamic client registration", entry.ID)
		}
		if !componentcatalog.ValidSecretName(name) {
			return cfg, status_grpc.Error(codes.InvalidArgument,
				"EnableConnector: oauth_client_secret_name is not a valid secret name")
		}
		cfg.OAuthClientID, cfg.OAuthClientSecretName = id, name
	case id != "" || name != "":
		return cfg, status_grpc.Errorf(codes.InvalidArgument,
			"EnableConnector: connector %q registers its own OAuth client and takes no client id or secret name", entry.ID)
	}
	return cfg, nil
}

// ListConnectors returns the tenant's enabled connectors with the state that
// the connector operator reported last.
func (s *ConnectorService) ListConnectors(
	ctx context.Context, _ *tenantv1.ListConnectorsRequest,
) (*tenantv1.ListConnectorsResponse, error) {
	tenant, err := s.callerTenant(ctx, "ListConnectors")
	if err != nil {
		return nil, err
	}
	rows, err := s.store.List(ctx, tenant)
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "ListConnectors: %v", err)
	}
	out := make([]*tenantv1.Connector, 0, len(rows))
	for _, r := range rows {
		c := &tenantv1.Connector{
			Id:              r.ConnectorID,
			Runtime:         string(connectorv1alpha1.ConnectorRuntimePod),
			Phase:           r.Phase,
			DiscoveredTools: r.DiscoveredTools,
			LastError:       r.LastError,
			Endpoint:        r.Endpoint,
			Variables:       r.Variables,
		}
		if entry, lerr := componentcatalog.LookupConnector(r.ConnectorID); lerr == nil {
			c.Shape = string(entry.Shape)
			c.ToolClass = entry.Class
		}
		out = append(out, c)
	}
	return &tenantv1.ListConnectorsResponse{Connectors: out}, nil
}

// DisableConnector removes the wish. The connector operator deletes the
// ConnectorInstance on its next pass, and its finalizer revokes the grant and
// removes the ToolHive resource, the NetworkPolicy and the credential secret.
func (s *ConnectorService) DisableConnector(
	ctx context.Context, req *tenantv1.DisableConnectorRequest,
) (*tenantv1.DisableConnectorResponse, error) {
	tenant, err := s.callerTenant(ctx, "DisableConnector")
	if err != nil {
		return nil, err
	}
	name := req.GetConnector()
	if name == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "DisableConnector: connector is required")
	}
	if err := s.store.Disable(ctx, tenant, name); err != nil {
		if errors.Is(err, tenantconnector.ErrNotEnabled) {
			return nil, status_grpc.Errorf(codes.NotFound, "DisableConnector: connector %q is not enabled", name)
		}
		return nil, status_grpc.Errorf(codes.Internal, "DisableConnector: %v", err)
	}
	return &tenantv1.DisableConnectorResponse{}, nil
}
