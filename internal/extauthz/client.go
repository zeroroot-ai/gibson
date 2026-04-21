// Package extauthz provides a thin gRPC client for the ext_authz service
// (gibson.extauthz.v1.ExtAuthzService). The daemon uses this to delegate
// capability-grant minting; no local JWT signing occurs here.
//
// The ext_authz address is taken from the EXT_AUTHZ_GRPC_ADDR environment
// variable, defaulting to "<release>-ext-authz:9001" (resolved at call time
// from the HELM_RELEASE_NAME env var, or "gibson-ext-authz:9001" if absent).
//
// On any transient error the caller should return codes.Unavailable — no local
// fallback minting is performed.
package extauthz

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
)

// Client is a thin gRPC client for the ext_authz service.
// It is safe for concurrent use.
type Client struct {
	conn *grpc.ClientConn
	addr string
}

// NewClient constructs a Client connected to the ext_authz gRPC endpoint.
// addr defaults to the EXT_AUTHZ_GRPC_ADDR environment variable; if unset,
// the address is derived from HELM_RELEASE_NAME as "<release>-ext-authz:9001",
// or "gibson-ext-authz:9001" when neither variable is set.
func NewClient(ctx context.Context) (*Client, error) {
	addr := os.Getenv("EXT_AUTHZ_GRPC_ADDR")
	if addr == "" {
		release := os.Getenv("HELM_RELEASE_NAME")
		if release == "" {
			release = "gibson"
		}
		addr = release + "-ext-authz:9001"
	}

	// In-cluster traffic; TLS is handled at the Envoy / mTLS layer.
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("extauthz: dial %s: %w", addr, err)
	}
	return &Client{conn: conn, addr: addr}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error { return c.conn.Close() }

// MintCapabilityGrant requests a new ES256 Capability Grant JWT from ext_authz.
// An FGA pre-check is performed by ext_authz; if the agent is not authorised
// to invoke the tool, PERMISSION_DENIED is returned unchanged.
//
// On ext_authz unavailability the method returns codes.Unavailable — the caller
// must propagate this to the client and not fall back to local minting.
func (c *Client) MintCapabilityGrant(
	ctx context.Context,
	agentID, toolID, tenant, inputsHash string,
	ttl time.Duration,
) (jwt string, jti string, expiresAt int64, err error) {
	if agentID == "" {
		return "", "", 0, status.Error(codes.InvalidArgument, "agent_id is required")
	}
	if toolID == "" {
		return "", "", 0, status.Error(codes.InvalidArgument, "tool_id is required")
	}

	req := &mintCapabilityGrantRequest{
		AgentID:    agentID,
		ToolID:     toolID,
		Tenant:     tenant,
		InputsHash: inputsHash,
		TTL:        durationpb.New(ttl),
	}

	resp, err := c.mintCapabilityGrant(ctx, req)
	if err != nil {
		// Translate connection-level errors to Unavailable so callers
		// can distinguish "ext_authz unreachable" from "FGA denied".
		if s, ok := status.FromError(err); ok && s.Code() == codes.Unavailable {
			return "", "", 0, status.Error(codes.Unavailable, "authorization service unavailable")
		}
		return "", "", 0, err
	}
	return resp.JWT, resp.JTI, resp.ExpiresAt, nil
}

// --------------------------------------------------------------------------
// Hand-rolled gRPC invocation — mirrors the ext_authz server's hand-rolled
// types. Replaced by buf-generated stubs once `make proto` runs in ext-authz
// and its go package is published and vendored here.
// --------------------------------------------------------------------------

const extAuthzServiceName = "gibson.extauthz.v1.ExtAuthzService"

type mintCapabilityGrantRequest struct {
	AgentID    string
	ToolID     string
	Tenant     string
	InputsHash string
	TTL        *durationpb.Duration
}

func (m *mintCapabilityGrantRequest) Reset()         {}
func (m *mintCapabilityGrantRequest) String() string { return m.AgentID }
func (m *mintCapabilityGrantRequest) ProtoMessage()  {}

type mintCapabilityGrantResponse struct {
	JWT       string
	JTI       string
	ExpiresAt int64
}

func (m *mintCapabilityGrantResponse) Reset()         {}
func (m *mintCapabilityGrantResponse) String() string { return m.JTI }
func (m *mintCapabilityGrantResponse) ProtoMessage()  {}

func (c *Client) mintCapabilityGrant(ctx context.Context, req *mintCapabilityGrantRequest) (*mintCapabilityGrantResponse, error) {
	resp := new(mintCapabilityGrantResponse)
	err := c.conn.Invoke(ctx, "/"+extAuthzServiceName+"/MintCapabilityGrant", req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
