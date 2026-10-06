// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	agentidentityv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// forgedGetCredentialRPC is the method that the forged grant claims.
const forgedGetCredentialRPC = "/gibson.component.v1.ComponentService/GetCredential"

// TestForgedCGJWT is the evidence for non-plugin-secret-isolation
// Requirement 4.3. Two independent layers each refuse a secret read:
//
//  1. A capability grant signed with a key that the platform did not issue
//     authenticates as nobody. The token is well formed and its signature is
//     valid over its bytes. Its kid is simply not a key of the platform.
//  2. The real grant of a checked-in agent authenticates the agent, and the
//     can_resolve decision still refuses it.
func TestForgedCGJWT(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	v := requireVenue(ctx, t)

	id := runID()
	secret := v.seedSecret(t, "forged-cg-"+id)

	t.Run("a grant signed with a foreign key reads nothing", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err, "generate the foreign key")
		forged, err := buildForgedCGJWT(priv, "e2e-forged-"+id, v.tenant, v.edge.origin.String(), []string{forgedGetCredentialRPC})
		require.NoError(t, err, "build the forged grant")

		// The connection carries no credential of its own: the forged grant
		// is the only identity on the call.
		plain := componentpb.NewComponentServiceClient(v.edge.dial(t))
		_, err = plain.GetCredential(metadata.AppendToOutgoingContext(ctx, "x-capability-grant", forged),
			&componentpb.GetCredentialRequest{Name: secret})
		require.Error(t, err, "a forged grant returned the secret")
		code := status.Code(err)
		require.True(t, code == codes.Unauthenticated || code == codes.PermissionDenied,
			"a forged grant must be refused at the edge, got %s: %v", code, err)
	})

	t.Run("the real grant of an agent is refused by can_resolve", func(t *testing.T) {
		agent := v.provision(ctx, t, agentidentityv1.PrincipalKind_PRINCIPAL_KIND_AGENT, "forged-cg-agent-"+id)
		requirePermissionDenied(t, "ComponentService.GetCredential as a checked-in agent", func() error {
			_, err := agent.credentials.GetCredential(ctx, &componentpb.GetCredentialRequest{Name: secret})
			return err //nolint:wrapcheck // the status error is the assertion subject
		})
	})
}

// buildForgedCGJWT builds a compact EdDSA JWT in the wire format of a
// capability grant: kid in the header, and the claim set of a grant in the
// payload. The signature is valid over the token bytes. Only the key is not a
// key of the platform.
func buildForgedCGJWT(priv ed25519.PrivateKey, kid, tenant, audience string, allowedRPCs []string) (string, error) {
	now := time.Now().UTC()
	header, err := json.Marshal(map[string]string{"typ": "JWT", "alg": "EdDSA", "kid": kid})
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss":             "https://forged-issuer.invalid",
		"aud":             audience,
		"sub":             "agent_principal:forged",
		"tenant":          tenant,
		"allowed_rpcs":    allowedRPCs,
		"recipient_class": "agent",
		"iat":             now.Unix(),
		"exp":             now.Add(5 * time.Minute).Unix(),
		"jti":             "forged-" + kid,
	})
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
