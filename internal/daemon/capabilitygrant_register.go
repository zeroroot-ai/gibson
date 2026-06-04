package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/capabilitygrant"
)

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

// capabilityGrantRegistrar registers a host+agent (the CapabilityGrantService).
type capabilityGrantRegistrar interface {
	RegisterCapabilityGrant(
		ctx context.Context,
		tenantID, ownerUserID, agentName, agentMode string,
		hostPublicKeyJWK, agentPublicKeyJWK json.RawMessage,
		bootstrapType, bootstrapCredential string,
	) (*capabilitygrant.RegisterCapabilityGrantResult, error)
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
func capabilityGrantRegisterHandler(verifier bootstrapVerifier, registrar capabilityGrantRegistrar) http.HandlerFunc {
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
		claims, err := verifier.VerifyBootstrapToken(token)
		if err != nil {
			// Do not echo the verification detail (it can leak token internals).
			http.Error(w, "invalid bootstrap credential", http.StatusUnauthorized)
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

		// The signed bootstrap claims are authoritative for identity: a component
		// registers under the name/mode it was enrolled as, never an arbitrary
		// body value. The body supplies only the host/agent public keys.
		agentName := claims.Name
		if agentName == "" {
			agentName = req.AgentName
		}
		agentMode := req.AgentMode
		if agentMode == "" {
			agentMode = "autonomous"
		}

		res, err := registrar.RegisterCapabilityGrant(
			r.Context(),
			claims.TenantID, claims.OwnerUserID, agentName, agentMode,
			req.HostKeyJWK, req.AgentKeyJWK,
			"bootstrap", token,
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
