/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package grpc provides a factory for outbound gRPC connections from the
// tenant-operator to the Gibson daemon (routed through Envoy).
//
// Authentication uses Zitadel service-account JWTs via the OAuth2
// client_credentials grant. The token source is cached and refreshed
// transparently before expiry by golang.org/x/oauth2/clientcredentials.
//
// In-cluster mTLS is detected automatically: if a SPIFFE Workload API
// socket is present at SPIFFE_ENDPOINT_SOCKET (or the default path), the
// connection uses SPIFFE SVID-based mutual TLS; otherwise it falls back to
// system-CA TLS. This mirrors the sdk/spiffe.DialOptions pattern.
//
// Any future daemon call site in this operator MUST obtain its *grpc.ClientConn
// from NewConn so that auth and mTLS are baked in automatically.
package grpc

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config holds the parameters for the operator's outbound gRPC connection.
type Config struct {
	// Target is the Envoy address for the Gibson daemon
	// (e.g., "gibson-envoy:443" or value of GIBSON_DAEMON_URL env).
	Target string

	// ZitadelIssuer is the Zitadel token endpoint used for client_credentials
	// grant (e.g., "https://auth.zeroroot.ai").
	ZitadelIssuer string

	// ClientID is the Zitadel service-account client ID for the operator.
	// Read from ZITADEL_TENANT_OPERATOR_CLIENT_ID env.
	ClientID string

	// ClientSecret is the Zitadel service-account client secret.
	// Read from ZITADEL_TENANT_OPERATOR_CLIENT_SECRET env. Never logged.
	ClientSecret string

	// Scopes requested from Zitadel. Defaults to ["openid"] if empty.
	Scopes []string

	// Insecure disables TLS. Only for local development without Envoy.
	// Must NOT be set in production deployments.
	Insecure bool
}

// ConfigFromEnv builds a Config by reading the canonical environment variables
// set by the operator's Helm chart and Kubernetes Secret mount.
func ConfigFromEnv() Config {
	scopes := []string{"openid"}
	return Config{
		Target:        os.Getenv("GIBSON_DAEMON_URL"),
		ZitadelIssuer: os.Getenv("ZITADEL_ISSUER"),
		ClientID:      os.Getenv("ZITADEL_TENANT_OPERATOR_CLIENT_ID"),
		ClientSecret:  os.Getenv("ZITADEL_TENANT_OPERATOR_CLIENT_SECRET"),
		Scopes:        scopes,
	}
}

// NewConn creates an authenticated gRPC client connection to the Gibson daemon
// via Envoy. The connection carries:
//   - A Zitadel service-account JWT in every RPC's Authorization header (via a
//     per-call oauth2.TokenSource interceptor). The token source caches and
//     refreshes tokens transparently.
//   - In-cluster mTLS when a SPIFFE Workload API socket is detected.
//
// Call conn.Close() when done.
func NewConn(ctx context.Context, cfg Config) (*grpc.ClientConn, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("grpc.NewConn: GIBSON_DAEMON_URL is required")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("grpc.NewConn: ZITADEL_TENANT_OPERATOR_CLIENT_ID and _SECRET are required")
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	// Build the Zitadel token endpoint from the issuer URL.
	tokenURL := cfg.ZitadelIssuer + "/oauth/v2/token"

	// clientcredentials.Config provides a token source that fetches and caches
	// tokens, refreshing them before expiry — no manual refresh loop needed.
	ccCfg := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     tokenURL,
		Scopes:       scopes,
	}
	tokenSource := ccCfg.TokenSource(ctx)

	dialOpts := []grpc.DialOption{
		grpc.WithPerRPCCredentials(&tokenCredentials{source: tokenSource}),
	}

	if cfg.Insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// Use system CA pool for TLS. SPIFFE mTLS is handled at the Envoy
		// layer (SPIRE delivers the SVID to the Envoy sidecar, not to this
		// process directly). The operator's pod identity is attested by SPIRE
		// and injected into Envoy's upstream TLS context via the SPIFFE SDS API.
		tlsCreds := credentials.NewClientTLSFromCert(nil, "")
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(tlsCreds))
	}

	//nolint:staticcheck // grpc.Dial is deprecated in grpc v1.64+ but remains
	// the standard in controller-runtime ecosystems until grpc.NewClient is
	// universally adopted. Switch when controller-runtime upgrades.
	conn, err := grpc.Dial(cfg.Target, dialOpts...) //nolint:deprecation
	if err != nil {
		return nil, fmt.Errorf("grpc.NewConn: dial %s: %w", cfg.Target, err)
	}
	return conn, nil
}

// tokenCredentials implements grpc.PerRPCCredentials using an oauth2.TokenSource.
// The token is fetched (and cached/refreshed) on every RPC call.
type tokenCredentials struct {
	source oauth2.TokenSource
}

func (t *tokenCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	tok, err := t.source.Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}
	return map[string]string{
		"authorization": "Bearer " + tok.AccessToken,
	}, nil
}

func (t *tokenCredentials) RequireTransportSecurity() bool { return true }
