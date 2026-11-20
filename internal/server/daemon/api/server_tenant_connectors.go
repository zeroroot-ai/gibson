// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantconnector"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// The connector operator pulls the connectors each tenant enabled, converges
// the ConnectorInstances, and reports their state (gibson#662). The three
// RPCs below are on the method list of the connector operator only.

// connectorStore returns the tenant connector store over the platform
// database, or Unavailable when the daemon has none.
func (s *DaemonServer) connectorStore() (*tenantconnector.Store, error) {
	db := s.platformDB
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	return tenantconnector.NewStore(db), nil
}

// ListDesiredConnectors returns one page of the (tenant, connector) pairs a tenant
// enabled, with the fields of the catalog entry. The read spans every tenant
// on purpose, so the method policy admits the connector operator only.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer method policy.
func (s *DaemonServer) ListDesiredConnectors(
	ctx context.Context, req *daemonoperatorv1.ListDesiredConnectorsRequest,
) (*daemonoperatorv1.ListDesiredConnectorsResponse, error) {
	store, err := s.connectorStore()
	if err != nil {
		return nil, err
	}
	sg, err := s.pageSigner(pageScopeDesiredConnectors)
	if err != nil {
		return nil, err
	}
	key, err := pageStart(sg, pageScopeDesiredConnectors, req.GetPageToken(), 2)
	if err != nil {
		return nil, err
	}
	var after *tenantconnector.PageKey
	if key != nil {
		after = &tenantconnector.PageKey{TenantID: key[0], ConnectorID: key[1]}
	}
	// One more row than the page tells whether a next page exists.
	size := pagetoken.Size(req.GetPageSize())
	rows, err := store.ListPage(ctx, after, size+1)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list desired connectors: %v", err)
	}
	out := &daemonoperatorv1.ListDesiredConnectorsResponse{}
	if len(rows) > size {
		rows = rows[:size]
		last := rows[size-1]
		out.NextPageToken = pageToken(sg, pageScopeDesiredConnectors, last.TenantID, last.ConnectorID)
	}
	// A page can hold fewer items than page_size, or none, and still have a
	// next page: a row whose connector left the catalog is not in the answer.
	out.Connectors = make([]*daemonoperatorv1.DesiredConnector, 0, len(rows))
	for _, r := range rows {
		// A row whose connector left the catalog is not desired any more: the
		// operator does not get it, and it removes the instance.
		entry, lerr := componentcatalog.LookupConnector(r.ConnectorID)
		if lerr != nil {
			continue
		}
		out.Connectors = append(out.Connectors, s.desiredConnector(r, entry))
	}
	return out, nil
}

// ReportConnectorStatus records the state that the connector operator reads
// from one ConnectorInstance. A report for a pair no tenant enabled changes
// nothing and answers updated=false.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer method policy.
func (s *DaemonServer) ReportConnectorStatus(
	ctx context.Context, req *daemonoperatorv1.ReportConnectorStatusRequest,
) (*daemonoperatorv1.ReportConnectorStatusResponse, error) {
	if req.GetTenantId() == "" || req.GetConnectorId() == "" || req.GetPhase() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id, connector_id and phase are required")
	}
	store, err := s.connectorStore()
	if err != nil {
		return nil, err
	}
	updated, err := store.ReportStatus(ctx, req.GetTenantId(), req.GetConnectorId(), tenantconnector.Status{
		Phase:     req.GetPhase(),
		LastError: req.GetLastError(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "report connector status: %v", err)
	}
	return &daemonoperatorv1.ReportConnectorStatusResponse{Updated: updated}, nil
}

// AdoptConnector records a connector that the daemon wrote as a
// ConnectorInstance before the table existed. Only a catalog connector can be
// adopted.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer method policy.
func (s *DaemonServer) AdoptConnector(
	ctx context.Context, req *daemonoperatorv1.AdoptConnectorRequest,
) (*daemonoperatorv1.AdoptConnectorResponse, error) {
	if req.GetTenantId() == "" || req.GetConnectorId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id and connector_id are required")
	}
	if _, err := componentcatalog.LookupConnector(req.GetConnectorId()); err != nil {
		return nil, status.Errorf(codes.NotFound, "adopt connector: %v", err)
	}
	store, err := s.connectorStore()
	if err != nil {
		return nil, err
	}
	if err := store.Adopt(ctx, req.GetTenantId(), req.GetConnectorId()); err != nil {
		return nil, status.Errorf(codes.Internal, "adopt connector: %v", err)
	}
	return &daemonoperatorv1.AdoptConnectorResponse{}, nil
}

// desiredConnector is what the connector operator needs to make the
// ConnectorInstance of one row.
//
// The endpoint and the egress allow-list come from ResolveEndpoint on each
// call, so a stored tenant endpoint is checked against the manifest of this
// release, not the manifest of the day when the tenant enabled the connector.
// When the check fails, the connector gets no endpoint and no egress host. The
// operator then reports it as Failed, and the connector never reaches a host
// that the manifest does not allow.
func (s *DaemonServer) desiredConnector(
	r tenantconnector.Connector, entry componentcatalog.ConnectorEntry,
) *daemonoperatorv1.DesiredConnector {
	res, err := entry.ResolveEndpoint(r.Endpoint)
	if err != nil {
		s.logger.Warn("connector endpoint is outside the catalog patterns",
			"connector", r.ConnectorID, "error", err)
		res = componentcatalog.ResolvedEndpoint{}
	}
	// The values that the tenant gave for the variables of a Hosted connector
	// are checked again, like the endpoint. When the check fails, the pod gets
	// no value and no egress host for them (gibson#1508).
	env := entry.Env
	egress := res.EgressAllow
	if len(entry.Variables) > 0 {
		vars, verr := entry.ResolveVariables(r.Variables)
		if verr != nil {
			s.logger.Warn("connector variables are outside the catalog rules",
				"connector", r.ConnectorID, "error", verr)
		} else {
			env = make(map[string]string, len(entry.Env)+len(vars.Env))
			for k, v := range entry.Env {
				env[k] = v
			}
			for k, v := range vars.Env {
				env[k] = v
			}
			egress = append(append([]string{}, egress...), vars.EgressAllow...)
		}
	}
	d := &daemonoperatorv1.DesiredConnector{
		TenantId:    r.TenantID,
		ConnectorId: r.ConnectorID,
		Shape:       string(entry.Shape),
		Image:       entry.Image,
		Endpoint:    res.Endpoint,
		Transport:   string(entry.Transport),
		Auth:        string(entry.Auth),
		EgressAllow: egress,
		Env:         env,
		Args:        entry.Args,
		Port:        int32(entry.Port), //nolint:gosec // G115: the catalog loader limits the port to 65535
	}
	d.CredentialHeader = entry.CredentialHeader.Name
	d.ImagePullSecret = entry.ImagePullSecret
	for _, c := range entry.Credentials {
		d.Credentials = append(d.Credentials, &daemonoperatorv1.ConnectorCredentialRef{
			Key: c.Secret, Property: c.Property, TargetEnv: c.Env,
		})
	}
	return d
}
