package client

import (
	"context"

	"google.golang.org/grpc/credentials"
)

// TokenCredentials implements credentials.PerRPCCredentials for bearer token authentication.
//
// This type adds an Authorization header with a bearer token to all gRPC requests.
// It implements the credentials.PerRPCCredentials interface from google.golang.org/grpc/credentials.
//
// The token is included as "Authorization: Bearer <token>" in the gRPC metadata for each RPC call.
// If the token is empty, no metadata is added, allowing the connection to proceed without authentication.
//
// Example usage:
//
//	creds := NewTokenCredentials("my-secret-token")
//	conn, err := grpc.Dial(endpoint,
//	    grpc.WithPerRPCCredentials(creds),
//	    grpc.WithTransportCredentials(insecure.NewCredentials()),
//	)
type TokenCredentials struct {
	token string
}

// NewTokenCredentials creates a new TokenCredentials with the given bearer token.
//
// The token will be sent with every RPC request as an Authorization header.
// An empty token is valid and results in no authentication metadata being sent.
//
// Parameters:
//   - token: Bearer token for authentication
//
// Returns:
//   - credentials.PerRPCCredentials: Credentials ready for use with grpc.WithPerRPCCredentials
//
// Example:
//
//	creds := NewTokenCredentials("gibson-admin-token")
//	conn, err := grpc.Dial("localhost:50002",
//	    grpc.WithPerRPCCredentials(creds),
//	    grpc.WithTransportCredentials(insecure.NewCredentials()),
//	)
func NewTokenCredentials(token string) credentials.PerRPCCredentials {
	return &TokenCredentials{token: token}
}

// GetRequestMetadata returns the authorization metadata for a request.
//
// This method is called by gRPC before each RPC to get authentication metadata.
// It returns a map with the "authorization" header set to "Bearer <token>".
//
// If the token is empty, returns nil to avoid sending an empty Authorization header,
// allowing the connection to proceed without authentication (useful for local daemons
// with trust_localhost enabled).
//
// The uri parameter contains the URI being requested but is not used for token auth.
//
// Parameters:
//   - ctx: Context for the request (unused for static token auth)
//   - uri: URI being requested (unused for token auth)
//
// Returns:
//   - map[string]string: Metadata with authorization header, or nil if no token
//   - error: Always nil (token auth does not perform additional validation)
//
// Example return value:
//
//	map[string]string{"authorization": "Bearer gibson-admin-token"}
func (t *TokenCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if t.token == "" {
		return nil, nil
	}
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

// RequireTransportSecurity indicates whether the credentials require TLS.
//
// Returns false to allow insecure connections for development and local daemons.
// In production deployments with remote daemons, you should configure TLS separately
// using grpc.WithTransportCredentials and TLS certificates.
//
// Note: Returning false here does NOT disable TLS if it's configured via transport
// credentials. It only indicates that these credentials can work over insecure connections
// (which is appropriate for development and localhost scenarios).
//
// Returns:
//   - bool: false (allows insecure connections)
func (t *TokenCredentials) RequireTransportSecurity() bool {
	return false // Allow insecure for development
}
