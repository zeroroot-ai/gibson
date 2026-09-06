// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

// CG-JWT signing identity for the daemon Minter (gibson#648, ADR-0045). The
// issuer/audience must match ext-authz's EXT_AUTHZ_CGJWT_ISSUER/_AUDIENCE for
// daemon-minted dispatch tokens to verify; the bootstrap token uses its own
// audience, so defaults are safe for the registration path on their own.
func cgJWTIssuer() string {
	if v := os.Getenv("GIBSON_CGJWT_ISSUER"); v != "" {
		return v
	}
	if v := os.Getenv("GIBSON_PUBLIC_URL"); v != "" {
		return v
	}
	return "gibson-daemon"
}

func cgJWTAudience() string {
	if v := os.Getenv("GIBSON_CGJWT_AUDIENCE"); v != "" {
		return v
	}
	return "gibson-daemon"
}

func cgJWTKeyID() string {
	if v := os.Getenv("GIBSON_CGJWT_KEY_ID"); v != "" {
		return v
	}
	return "cg-v1"
}

// cgSigningKeyDir names the projected Secret volume holding the daemon's
// dedicated CG signing key (and, during a rotation, the outgoing one).
//
// The default matches the chart's mount point. When nothing is mounted there
// the Minter falls back to the legacy master-KEK derivation and says so at
// startup, so an upgrade that predates the chart change does not take
// capability grants down.
func cgSigningKeyDir() string {
	if v := os.Getenv("GIBSON_CGJWT_SIGNING_KEY_DIR"); v != "" {
		return v
	}
	return "/etc/gibson/cg-signing-key"
}

// Capability-Grant host registration endpoint (epic unified-cg-identity,
// ADR-0045, gibson#648).
//
// POST /capabilitygrant/v1/register, served on the daemon's pre-auth listener.
// A component proves its identity for FIRST registration with a daemon-signed
// bootstrap token (Authorization: Bearer <bootstrap>); the handler verifies it
// with the daemon's own CG key (no gateway JWT), then upserts the host + agent
// and resolves the owner's FGA capabilities. Subsequent registrations from the
// same host use a host+JWT (handled where the host key already exists; not yet
// served here — first-registration bootstrap is the unblocking path).
//
// Request/response shapes mirror opensource/sdk/capabilitygrant exactly.

// bootstrapVerifier verifies a bootstrap token (the daemon Minter).
type bootstrapVerifier interface {
	VerifyBootstrapToken(token string) (*capabilitygrant.BootstrapClaims, error)
}

// capabilityGrantRegistrar registers a host+agent and verifies a host+jwt for
// re-registration (the CapabilityGrantService).
type capabilityGrantRegistrar interface {
	RegisterCapabilityGrant(
		ctx context.Context,
		tenantID, ownerUserID, agentName, agentMode, principalRef string,
		hostPublicKeyJWK, agentPublicKeyJWK json.RawMessage,
		bootstrapType, bootstrapCredential string,
		capabilityCeiling []string,
	) (*capabilitygrant.RegisterCapabilityGrantResult, error)

	// VerifyHostJWT authenticates a re-registration (the caller already holds a
	// registered host key) by verifying a host+jwt against the stored host key.
	// expectedAud is the daemon's register-endpoint URL.
	VerifyHostJWT(ctx context.Context, token, expectedAud string) (*capabilitygrant.HostClaims, error)
}

// cgRegisterRequest mirrors the SDK's registrationRequest.
type cgRegisterRequest struct {
	HostID      string          `json:"host_id"`
	AgentName   string          `json:"agent_name"`
	AgentMode   string          `json:"agent_mode"`
	HostKeyJWK  json.RawMessage `json:"host_key_jwk"`
	AgentKeyJWK json.RawMessage `json:"agent_key_jwk"`
}

// cgRegisterCapability mirrors the SDK's Capability wire shape.
type cgRegisterCapability struct {
	Name         string `json:"capability_name"`
	ComponentRef string `json:"component_ref"`
}

// cgRegisterResponse mirrors the SDK's registrationResponse.
type cgRegisterResponse struct {
	AgentID        string                 `json:"agent_id"`
	Capabilities   []cgRegisterCapability `json:"capabilities"`
	ComponentScope string                 `json:"component_scope"`
}

// capabilityGrantRegisterHandler returns the POST register handler. verifier and
// registrar are required; when either is nil the endpoint reports 503 so a
// partial wire-up is safe.
func capabilityGrantRegisterHandler(
	verifier bootstrapVerifier,
	registrar capabilityGrantRegistrar,
	svidEnroller pluginEnroller,
	publicURL string,
	logger *slog.Logger,
) http.HandlerFunc {
	if logger == nil {
		logger = slog.Default()
	}
	// The host+jwt audience the SDK signs against is the register URL advertised
	// in the discovery document — derived from the same public base URL.
	registerAudience := strings.TrimRight(publicURL, "/") + capabilityGrantRegisterPath
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if verifier == nil || registrar == nil {
			http.Error(w, "capability-grant registration not configured", http.StatusServiceUnavailable)
			return
		}

		token, err := bearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		var req cgRegisterRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.HostKeyJWK) == 0 || len(req.AgentKeyJWK) == 0 {
			http.Error(w, "host_key_jwk and agent_key_jwk are required", http.StatusBadRequest)
			return
		}

		// Resolve the authenticated identity from the credential type:
		//   - host+jwt → RE-registration: the caller proves possession of an
		//     already-registered host key; tenant/owner/principal come from the
		//     stored host record (no bootstrap claim is present).
		//   - otherwise → FIRST registration: a daemon-signed bootstrap token
		//     carries the signed identity (the authoritative name/mode/principal).
		var tenantID, ownerUserID, principalRef, signedName, bootstrapType string
		// capabilityCeiling comes ONLY from the verified bootstrap scope. A
		// re-registration presents no bootstrap credential and so states no
		// ceiling; the request body never contributes one.
		var capabilityCeiling []string
		switch {
		case jwtTyp(token) == capabilitygrant.HostTokenType:
			hc, verr := registrar.VerifyHostJWT(r.Context(), token, registerAudience)
			if verr != nil {
				// The response stays generic (a verification detail can leak token
				// internals), but the daemon MUST say which check failed. A bare
				// 401 sent every reader looking at their credential, which was
				// valid — the daemon simply could not find the host under the id
				// the client signs (gibson#1207).
				logger.WarnContext(r.Context(), "capability-grant: host re-registration rejected",
					slog.String("audience_expected", registerAudience),
					slog.String("error", verr.Error()),
				)
				http.Error(w, "invalid host credential", http.StatusUnauthorized)
				return
			}
			tenantID, ownerUserID, principalRef, bootstrapType = hc.TenantID, hc.OwnerUserID, hc.PrincipalRef, "host_jwt"
		case svidEnroller != nil && jwtTyp(token) != capabilitygrant.BootstrapTokenType:
			// SPIFFE-SVID first-party plugin enrollment (ADR-0066). The credential
			// is neither a host+jwt nor a daemon-minted bootstrap token, so it is a
			// SPIRE JWT-SVID. Verify it against the SPIRE bundle, provision the
			// plugin principal, then fall through to the shared
			// RegisterCapabilityGrant below (bootstrapType spiffe_svid is NOT
			// single-use — the SVID is re-presented on every start).
			id, verr := svidEnroller.ResolvePluginBySVID(r.Context(), token, registerAudience)
			if verr != nil {
				if errors.Is(verr, ErrSVIDUnverified) {
					logger.WarnContext(r.Context(), "capability-grant: SVID enrollment rejected",
						slog.String("error", verr.Error()),
					)
					http.Error(w, "invalid enrollment credential", http.StatusUnauthorized)
					return
				}
				// A verified SVID whose provisioning failed is an internal fault.
				logger.ErrorContext(r.Context(), "capability-grant: SVID enrollment provisioning failed",
					slog.String("error", verr.Error()),
				)
				http.Error(w, "enrollment failed", http.StatusInternalServerError)
				return
			}
			tenantID, ownerUserID, principalRef, signedName, bootstrapType =
				id.TenantID, id.OwnerUserID, id.PrincipalRef, id.Name, capabilitygrant.BootstrapTypeSPIFFESVID
		default:
			claims, verr := verifier.VerifyBootstrapToken(token)
			if verr != nil {
				// Generic to the caller, specific in the log — same reasoning as
				// the host path above.
				logger.WarnContext(r.Context(), "capability-grant: bootstrap registration rejected",
					slog.String("error", verr.Error()),
				)
				http.Error(w, "invalid bootstrap credential", http.StatusUnauthorized)
				return
			}
			tenantID, ownerUserID, principalRef, signedName, bootstrapType = claims.TenantID, claims.OwnerUserID, claims.PrincipalID, claims.Name, "bootstrap"
			capabilityCeiling = claims.CapabilityCeiling
		}

		// On first registration the signed claim name is authoritative; on
		// re-registration (no signed name) the request body supplies it.
		agentName := signedName
		if agentName == "" {
			agentName = req.AgentName
		}
		agentMode := req.AgentMode
		if agentMode == "" {
			agentMode = "autonomous"
		}

		res, err := registrar.RegisterCapabilityGrant(
			r.Context(),
			tenantID, ownerUserID, agentName, agentMode, principalRef,
			req.HostKeyJWK, req.AgentKeyJWK,
			bootstrapType, token, capabilityCeiling,
		)
		if err != nil {
			http.Error(w, "registration failed", http.StatusInternalServerError)
			return
		}

		resp := cgRegisterResponse{
			AgentID:        res.AgentID,
			ComponentScope: res.ComponentScope,
			Capabilities:   make([]cgRegisterCapability, 0, len(res.Capabilities)),
		}
		for _, c := range res.Capabilities {
			resp.Capabilities = append(resp.Capabilities, cgRegisterCapability{
				Name:         c.Name,
				ComponentRef: c.ComponentRef,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// jwtTyp base64url-decodes a compact JWT's header (WITHOUT verifying) to read
// its `typ`, so the register handler can dispatch host+jwt re-registration vs a
// bootstrap token. Verification happens afterward in the chosen path; this only
// routes. Returns "" on any parse failure (→ the bootstrap path, which then
// rejects it).
func jwtTyp(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h.Typ
}

// bearerToken extracts the token from an Authorization: Bearer header.
func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", errors.New("missing or malformed Authorization: Bearer header")
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if tok == "" {
		return "", errors.New("empty bearer token")
	}
	return tok, nil
}
