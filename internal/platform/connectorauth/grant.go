// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package connectorauth owns a connector's OAuth token lifecycle.
//
// A connector fronts a vendor MCP server (ADR-0047, ADR-0049). When that
// vendor requires OAuth — GitLab's first-party MCP server does, with no
// personal-access-token path — something has to acquire and refresh a token.
// ADR-0064 decides that something is the platform, never the bridge, and the
// reason is in the code rather than a preference: GetCredential is the only
// credential RPC a plugin has. There is no write-back and no rotate. OAuth 2.1
// mandates refresh-token rotation, so a bridge refreshing its own token would
// receive a rotated refresh token it cannot persist and would break
// permanently on the next restart.
//
// So the bridge presents a credential it reads, and this package produces it.
//
// TWO SECRETS, NOT ONE. The Grant — refresh token, client id, token endpoint,
// scope, expiry — is platform-only and bound to no component. The access token
// is a separate short-lived secret and is the only one a connector can
// resolve. The split is the point: what runs beside the bridge is a
// third-party vendor MCP server, the code this platform classifies as
// untrusted and runs in a microVM for that reason. If the grant were one
// secret, a compromise would mean standing access to the customer's system
// rather than a credential that expires.
//
// The isolation is structural rather than conventional. The FGA model permits
// can_resolve on a secret only for a plugin_principal, so a secret with no
// such tuple is unresolvable by every component. This package therefore keeps
// the grant platform-only by never asking for a tuple on it.
package connectorauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Grant is a connector's OAuth grant: everything needed to mint a fresh access
// token without a human, and nothing a connector is allowed to see.
//
// Stored as one opaque JSON blob because the secrets broker holds bytes under
// a single value key — there is no structured or multi-field secret.
type Grant struct {
	// RefreshToken mints new access tokens. The reason this type is
	// platform-only.
	RefreshToken string `json:"refresh_token"`

	// TokenEndpoint is the vendor's OAuth token URL, e.g.
	// https://gitlab.example.com/oauth/token.
	TokenEndpoint string `json:"token_endpoint"`

	// ClientID identifies the OAuth application. ClientSecret is empty for a
	// public client using PKCE, which is what dynamic client registration
	// produces.
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`

	// Scope is what the human consented to. Carried so a re-authorization can
	// be compared against it, and so an operator can see it.
	Scope string `json:"scope,omitempty"`

	// RevocationEndpoint is the vendor's OAuth revocation URL, when the
	// vendor advertises one (RFC 7009). Recorded so revoking the connector
	// can revoke the refresh token at the vendor too, rather than only
	// deleting the platform's copy.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// AuthorizedBy is the human who ran the authorization, and AuthorizedAt is
	// when. ADR-0064 requires both to be recorded and surfaced: a connector is
	// a service account with an audit trail in front of it, and "who is this
	// connector acting as" must have an answer on screen. Naming the boundary
	// is what keeps it honest — implying per-user fidelity the vendor's own
	// audit log will not show is how this fails an enterprise review.
	AuthorizedBy string    `json:"authorized_by"`
	AuthorizedAt time.Time `json:"authorized_at"`

	// Static marks a grant that backs a customer-supplied static credential
	// (an `auth: secret` connector, ADR-0015): a personal access token the
	// tenant admin handed the platform through SetConnectorSecret. The
	// credential itself lives in the access secret, exactly where an OAuth
	// access token lives, so the materializer treats both modes alike. A
	// static grant has no refresh token and no expiry the platform manages:
	// the refresher never touches it, and revoking it deletes the pair with
	// no vendor call. It still records the accountable human.
	Static bool `json:"static,omitempty"`
}

// Validate reports why a grant is unusable, or nil.
func (g *Grant) Validate() error {
	var missing []string
	if !g.Static {
		// Only an OAuth grant mints tokens; a static grant carries none of
		// the refresh material.
		if g.RefreshToken == "" {
			missing = append(missing, "refresh_token")
		}
		if g.TokenEndpoint == "" {
			missing = append(missing, "token_endpoint")
		}
		if g.ClientID == "" {
			missing = append(missing, "client_id")
		}
	}
	if g.AuthorizedBy == "" {
		// Not cosmetic. A grant with no recorded human is a service account
		// nobody is accountable for, which is the thing ADR-0064 refuses.
		missing = append(missing, "authorized_by")
	}
	if len(missing) > 0 {
		return fmt.Errorf("connector grant is incomplete: missing %s", strings.Join(missing, ", "))
	}
	return nil
}

// MarshalGrant renders a grant for the secrets broker.
func MarshalGrant(g *Grant) ([]byte, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("connectorauth: marshal grant: %w", err)
	}
	return b, nil
}

// UnmarshalGrant parses a grant read from the secrets broker.
//
// A parse failure names the secret, never its content: the bytes are a refresh
// token and must not reach a log through an error string.
func UnmarshalGrant(b []byte) (*Grant, error) {
	if len(b) == 0 {
		return nil, errors.New("connector grant is empty")
	}
	var g Grant
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, errors.New("connector grant is not valid JSON")
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return &g, nil
}

// AccessToken is the short-lived credential a connector actually presents,
// with the expiry the platform's refresher schedules against.
//
// The two fields land in two different secrets. The connector presents the
// resolved bytes of its auth secret verbatim (`Authorization: Bearer <bytes>`),
// so the connector-visible secret holds the RAW token and
// nothing else; the expiry is platform bookkeeping and lives in a separate
// platform-only metadata secret.
type AccessToken struct {
	Token     string    `json:"access_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GrantSecretName is the broker name of a connector's grant.
//
// PLATFORM-ONLY. Never bind this name to a component: doing so hands a
// third-party vendor server standing access rather than a credential that
// expires.
func GrantSecretName(connector string) string {
	return "cred:connector/" + connector + "/grant"
}

// AccessSecretName is the broker name of a connector's access token. It holds
// the raw token bytes and nothing else, because the connector presents the
// resolved value verbatim as the credential.
func AccessSecretName(connector string) string {
	return "cred:connector/" + connector + "/access"
}

// AccessMetaSecretName is the broker name of the platform's bookkeeping for a
// connector's access token — currently the expiry the refresher schedules
// against, as an AccessToken JSON blob.
//
// PLATFORM-ONLY, like the grant. Never bind this name to a component: the
// connector needs the token, not the platform's schedule.
func AccessMetaSecretName(connector string) string {
	return "cred:connector/" + connector + "/access-meta"
}
