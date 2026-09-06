// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/sdk/auth"
)

// CatalogGate is the narrow authorizer slice the connector service needs for
// the platform catalog gate (ADR-0067, closing the ADR-0014 TODO): is a
// catalog entry platform_enabled? The full authz.Authorizer satisfies it.
type CatalogGate interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error)
}

// systemTenantRef is the singleton platform publisher — the only subject the
// model admits for `component.platform_enabled`.
const systemTenantRef = "system_tenant:_system"

// ConnectorService is the daemon API a person drives to enable and manage
// third-party MCP connectors (ADR-0014). It serves the connector lifecycle:
// catalog, enable, list, disable. The RPC is the source of truth; the gibson
// CLI and the dashboard are thin clients of it.
//
// EnableConnector writes a ConnectorInstance CR into the tenant namespace with
// a NARROW, RBAC-scoped controller-runtime client. The write is declarative:
// the connector-operator does all the reconcile work (ToolHive MCPServer /
// MCPRemoteProxy, NetworkPolicy, credential ExternalSecret). This service never
// touches ToolHive directly.
type ConnectorService struct {
	tenantv1.UnimplementedConnectorServiceServer

	// kube is the narrow client that writes ConnectorInstance CRs into tenant
	// namespaces. Its RBAC is limited to ConnectorInstance CRUD (see the daemon
	// ServiceAccount role in the deploy chart).
	kube client.Client

	// gate answers the platform catalog gate: an entry without its
	// platform_enabled tuple is invisible to ListCatalog and refused by
	// EnableConnector. Required — the service is not registered without it.
	gate CatalogGate
}

// NewConnectorService constructs the service over the given ConnectorInstance
// client and catalog gate.
func NewConnectorService(kube client.Client, gate CatalogGate) *ConnectorService {
	return &ConnectorService{kube: kube, gate: gate}
}

// tenantNamespace resolves the caller's tenant namespace from the ext-authz
// context, and only from there. The namespace is tenant-<id> (owner_ref.go).
func (s *ConnectorService) tenantNamespace(ctx context.Context, rpc string) (string, error) {
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return "", status_grpc.Errorf(codes.PermissionDenied, "%s: missing tenant in context", rpc)
	}
	return "tenant-" + tenantID.String(), nil
}

// ListCatalog returns the curated connectors the tenant may enable.
func (s *ConnectorService) ListCatalog(
	ctx context.Context, _ *tenantv1.ListCatalogRequest,
) (*tenantv1.ListCatalogResponse, error) {
	// A caller must be a tenant member; ext-authz enforces the RPC annotation,
	// so the presence of a tenant in the context is the gate here.
	if _, err := s.tenantNamespace(ctx, "ListCatalog"); err != nil {
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
		})
	}
	return &tenantv1.ListCatalogResponse{Entries: out}, nil
}

// EnableConnector creates a ConnectorInstance for the catalog entry in the
// caller's tenant namespace. The operator reconciles it. An OAuth connector
// comes up AuthorizationRequired until a human authorizes it.
func (s *ConnectorService) EnableConnector(
	ctx context.Context, req *tenantv1.EnableConnectorRequest,
) (*tenantv1.EnableConnectorResponse, error) {
	ns, err := s.tenantNamespace(ctx, "EnableConnector")
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
	ci := entry.BuildConnectorInstance(ns)
	if err := s.kube.Create(ctx, ci); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, status_grpc.Errorf(codes.AlreadyExists,
				"EnableConnector: connector %q is already enabled", entry.ID)
		}
		return nil, status_grpc.Errorf(codes.Internal, "EnableConnector: create ConnectorInstance: %v", err)
	}
	return &tenantv1.EnableConnectorResponse{
		Connector: ci.Name,
		Phase:     string(ci.Status.Phase),
	}, nil
}

// ListConnectors returns the tenant's enabled connectors and their live status.
func (s *ConnectorService) ListConnectors(
	ctx context.Context, _ *tenantv1.ListConnectorsRequest,
) (*tenantv1.ListConnectorsResponse, error) {
	ns, err := s.tenantNamespace(ctx, "ListConnectors")
	if err != nil {
		return nil, err
	}
	var list connectorv1alpha1.ConnectorInstanceList
	if err := s.kube.List(ctx, &list, client.InNamespace(ns)); err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "ListConnectors: %v", err)
	}
	out := make([]*tenantv1.Connector, 0, len(list.Items))
	for i := range list.Items {
		ci := &list.Items[i]
		out = append(out, &tenantv1.Connector{
			Id:              ci.Name,
			Shape:           string(ci.Spec.Shape),
			Runtime:         string(ci.Spec.Runtime),
			Phase:           string(ci.Status.Phase),
			DiscoveredTools: ci.Status.DiscoveredTools,
			LastError:       ci.Status.LastError,
		})
	}
	return &tenantv1.ListConnectorsResponse{Connectors: out}, nil
}

// DisableConnector deletes the ConnectorInstance. The operator cascade-removes
// the ToolHive resource, the NetworkPolicy, and the credential secret.
func (s *ConnectorService) DisableConnector(
	ctx context.Context, req *tenantv1.DisableConnectorRequest,
) (*tenantv1.DisableConnectorResponse, error) {
	ns, err := s.tenantNamespace(ctx, "DisableConnector")
	if err != nil {
		return nil, err
	}
	name := req.GetConnector()
	if name == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "DisableConnector: connector is required")
	}
	ci := &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}
	if err := s.kube.Delete(ctx, ci); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, status_grpc.Errorf(codes.NotFound, "DisableConnector: connector %q is not enabled", name)
		}
		return nil, status_grpc.Errorf(codes.Internal, "DisableConnector: %v", err)
	}
	return &tenantv1.DisableConnectorResponse{}, nil
}
