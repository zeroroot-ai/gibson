package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentConfigHandler_ServesSDKContract(t *testing.T) {
	const public = "https://api.zeroroot.ai:30443"
	srv := httptest.NewServer(agentConfigHandler(public))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + agentConfigWellKnownPath)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Decode into the exact shape the SDK reads.
	var doc agentConfigDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.ProtocolVersion != "1.0" {
		t.Errorf("protocol_version = %q, want 1.0", doc.ProtocolVersion)
	}
	if doc.Issuer != public {
		t.Errorf("issuer = %q, want %q", doc.Issuer, public)
	}
	wantRegister := public + capabilityGrantRegisterPath
	if doc.Endpoints.Register != wantRegister {
		t.Errorf("endpoints.register = %q, want %q", doc.Endpoints.Register, wantRegister)
	}
	if !strings.HasSuffix(doc.JWKSURI, daemonJWKSPath) {
		t.Errorf("jwks_uri = %q, want suffix %q", doc.JWKSURI, daemonJWKSPath)
	}
	if len(doc.SupportedModes) == 0 {
		t.Error("supported_modes is empty")
	}
}

func TestAgentConfigHandler_UnconfiguredIsServiceUnavailable(t *testing.T) {
	srv := httptest.NewServer(agentConfigHandler(""))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + agentConfigWellKnownPath)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when GIBSON_PUBLIC_URL is unset", resp.StatusCode)
	}
}

// TestAgentConfigDocument_MatchesSDKFieldNames pins the JSON field names against
// the SDK contract (opensource/sdk/capabilitygrant.DiscoveryDocument). A rename
// here silently breaks every external component's Discover().
func TestAgentConfigDocument_MatchesSDKFieldNames(t *testing.T) {
	b, err := json.Marshal(buildAgentConfigDocument("https://x"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	for _, field := range []string{
		`"protocol_version"`, `"provider_name"`, `"issuer"`, `"default_location"`,
		`"supported_modes"`, `"endpoints"`, `"register"`, `"jwks_uri"`,
	} {
		if !strings.Contains(got, field) {
			t.Errorf("discovery JSON missing field %s\ngot: %s", field, got)
		}
	}
}
