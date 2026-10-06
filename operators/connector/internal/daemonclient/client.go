// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemonclient is the connector-operator's client to the daemon's
// DaemonOperatorService. The ConnectorInstance finalizer revokes a connector's
// grant on delete (ADR-0061, gibson#1566), and the ConnectorInstance
// controller reads the connector's credential state so the CR reports Degraded
// instead of a silent Active (ADR-0061).
//
// The operator has no secret-store client by design: the daemon owns the
// Grant and the access pair, so the operator only carries the (tenant,
// connector) pair to it. The dial is SPIFFE mTLS over the SPIRE Workload API
// (ADR-0002); the daemon authorizes the connector-operator SVID for exactly
// these two RPCs (internal/server/daemon/operator_method_policy.go).
package daemonclient

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	daemontransport "github.com/zeroroot-ai/gibson/operators/tenant/pkg/transport/daemon"
)

// Client reads and revokes connector grants through the daemon. Construct exactly one
// per operator process and reuse it: the underlying X509Source streams SVID
// rotations for the life of the connection.
type Client struct {
	transport *daemontransport.Client
	operator  daemonoperatorv1.DaemonOperatorServiceClient
}

// New dials the daemon at addr over SPIFFE mTLS, pinning daemonSVID as the
// server identity. Fails when the SPIRE Workload API is unreachable, so a
// misconfigured operator fails at boot rather than at the first delete.
func New(ctx context.Context, addr, daemonSVID string) (*Client, error) {
	transport, err := daemontransport.NewClient(ctx, daemontransport.Options{
		Addr:       addr,
		DaemonSVID: daemonSVID,
	})
	if err != nil {
		return nil, fmt.Errorf("connector-operator daemon client: %w", err)
	}
	c := NewWithConn(transport.Conn())
	c.transport = transport
	return c, nil
}

// NewWithConn builds a Client over an existing connection. Tests pass a
// bufconn-backed or fake connection; production uses New.
func NewWithConn(conn grpc.ClientConnInterface) *Client {
	return &Client{operator: daemonoperatorv1.NewDaemonOperatorServiceClient(conn)}
}

// Revoke revokes the tenant's connector grant. Idempotent on the daemon side:
// a connector with no grant is a successful no-op.
func (c *Client) Revoke(ctx context.Context, tenantID, connector string) error {
	_, err := c.operator.RevokeConnectorGrant(ctx, &daemonoperatorv1.RevokeConnectorGrantRequest{
		TenantId:  tenantID,
		Connector: connector,
	})
	if err != nil {
		return fmt.Errorf("revoke connector grant %s/%s: %w", tenantID, connector, err)
	}
	return nil
}

// AuthStatus reports the tenant connector's credential state: whether a grant
// is stored, whether the last refresh failed, and the vendor's own error when
// it did. It returns no credential material, so the controller can put the
// reason straight on the ConnectorInstance condition.
func (c *Client) AuthStatus(ctx context.Context, tenantID, connector string) (*tenantv1.GetConnectorAuthStatusResponse, error) {
	resp, err := c.operator.GetConnectorAuthStatus(ctx, &daemonoperatorv1.GetConnectorAuthStatusRequest{
		TenantId:  tenantID,
		Connector: connector,
	})
	if err != nil {
		return nil, fmt.Errorf("connector auth status %s/%s: %w", tenantID, connector, err)
	}
	return resp.GetStatus(), nil
}

// ListDesiredConnectors pulls every connector that a tenant enabled, with the
// fields of the catalog entry (gibson#662).
func (c *Client) ListDesiredConnectors(ctx context.Context) ([]*daemonoperatorv1.DesiredConnector, error) {
	resp, err := c.operator.ListDesiredConnectors(ctx, &daemonoperatorv1.ListDesiredConnectorsRequest{})
	if err != nil {
		return nil, fmt.Errorf("list desired connectors: %w", err)
	}
	return resp.GetConnectors(), nil
}

// ReportConnectorStatus reports the state of one ConnectorInstance to the
// daemon (gibson#662).
func (c *Client) ReportConnectorStatus(ctx context.Context, req *daemonoperatorv1.ReportConnectorStatusRequest) error {
	if _, err := c.operator.ReportConnectorStatus(ctx, req); err != nil {
		return fmt.Errorf("report connector status %s/%s: %w", req.GetTenantId(), req.GetConnectorId(), err)
	}
	return nil
}

// AdoptConnector records a ConnectorInstance that the daemon wrote before it
// kept the desired state in its table (gibson#662).
func (c *Client) AdoptConnector(ctx context.Context, tenantID, connector string) error {
	if _, err := c.operator.AdoptConnector(ctx, &daemonoperatorv1.AdoptConnectorRequest{
		TenantId: tenantID, ConnectorId: connector,
	}); err != nil {
		return fmt.Errorf("adopt connector %s/%s: %w", tenantID, connector, err)
	}
	return nil
}

// Close releases the connection and the SPIRE X509Source. Idempotent; a
// Client built with NewWithConn owns no transport and closes nothing.
func (c *Client) Close() error {
	if c == nil || c.transport == nil {
		return nil
	}
	if err := c.transport.Close(); err != nil {
		return fmt.Errorf("connector-operator daemon client: close: %w", err)
	}
	return nil
}
