package registry

import "context"

// tokenCredentials implements credentials.PerRPCCredentials for bearer token authentication.
//
// This type adds an Authorization header with a bearer token to all gRPC requests.
// It implements the credentials.PerRPCCredentials interface from google.golang.org/grpc/credentials.
//
// Example usage:
//
//	creds := &tokenCredentials{token: "my-secret-token"}
//	conn, err := grpc.Dial(endpoint,
//	    grpc.WithPerRPCCredentials(creds),
//	    grpc.WithTransportCredentials(insecure.NewCredentials()),
//	)
type tokenCredentials struct {
	token string
}

// GetRequestMetadata returns the authorization metadata for a request.
//
// This method is called by gRPC before each RPC to get authentication metadata.
// It returns a map with the "authorization" header set to "Bearer <token>".
//
// If the token is empty, returns nil to avoid sending an empty Authorization header.
//
// The uri parameter contains the URI being requested but is not used for token auth.
func (t *tokenCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if t.token == "" {
		return nil, nil
	}
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

// RequireTransportSecurity indicates whether the credentials require TLS.
//
// Returns false to allow insecure connections for development.
// In production, you should use TLS with these credentials by configuring
// the gRPC connection with TLS transport credentials.
func (t *tokenCredentials) RequireTransportSecurity() bool {
	return false // Allow insecure for development
}
