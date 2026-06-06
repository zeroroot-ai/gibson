package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/capabilitygrant"
)

// hostJWTToken returns a token whose header typ is host+jwt so the register
// handler routes to the host+jwt path. The signature is irrelevant here — the
// fake registrar's VerifyHostJWT is stubbed (real verification is unit-tested in
// the capabilitygrant package).
func hostJWTToken() string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"host+jwt","alg":"EdDSA"}`))
	return hdr + ".e30.c2ln" // header.{}.sig
}

type fakeBootstrapVerifier struct {
	claims *capabilitygrant.BootstrapClaims
	err    error
}

func (f fakeBootstrapVerifier) VerifyBootstrapToken(string) (*capabilitygrant.BootstrapClaims, error) {
	return f.claims, f.err
}

type fakeRegistrar struct {
	gotTenant, gotOwner, gotName, gotMode, gotPrincipal, gotBootstrapType string
	result                                                                *capabilitygrant.RegisterCapabilityGrantResult
	err                                                                   error

	// host+jwt re-registration path.
	hostClaims *capabilitygrant.HostClaims
	hostErr    error
	gotHostAud string
}

func (f *fakeRegistrar) RegisterCapabilityGrant(
	_ context.Context,
	tenantID, ownerUserID, agentName, agentMode, principalRef string,
	_, _ json.RawMessage,
	bootstrapType, _ string,
) (*capabilitygrant.RegisterCapabilityGrantResult, error) {
	f.gotTenant, f.gotOwner, f.gotName, f.gotMode, f.gotPrincipal, f.gotBootstrapType = tenantID, ownerUserID, agentName, agentMode, principalRef, bootstrapType
	return f.result, f.err
}

func (f *fakeRegistrar) VerifyHostJWT(_ context.Context, _, expectedAud string) (*capabilitygrant.HostClaims, error) {
	f.gotHostAud = expectedAud
	return f.hostClaims, f.hostErr
}

func postRegister(t *testing.T, h http.HandlerFunc, auth, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, capabilityGrantRegisterPath, bytes.NewBufferString(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

const validRegBody = `{"host_id":"h1","agent_name":"body-name","agent_mode":"autonomous","host_key_jwk":{"kty":"OKP"},"agent_key_jwk":{"kty":"OKP"}}`

func TestCGRegister_HappyPath_SDKContract(t *testing.T) {
	verifier := fakeBootstrapVerifier{claims: &capabilitygrant.BootstrapClaims{
		TenantID: "acme", OwnerUserID: "user-1", PrincipalID: "agent_principal:9", Kind: "agent", Name: "hello-agent",
	}}
	reg := &fakeRegistrar{result: &capabilitygrant.RegisterCapabilityGrantResult{
		AgentID:        "agent-xyz",
		ComponentScope: "component:hello-agent",
		Capabilities:   []capabilitygrant.Capability{{Name: "can_invoke:tool:nmap", ComponentRef: "component:nmap"}},
	}}
	h := capabilityGrantRegisterHandler(verifier, reg, "https://api.test")

	rr := postRegister(t, h, "Bearer abc.def.ghi", validRegBody)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	// Decode into the exact SDK response shape.
	var resp struct {
		AgentID      string `json:"agent_id"`
		Capabilities []struct {
			Name         string `json:"capability_name"`
			ComponentRef string `json:"component_ref"`
		} `json:"capabilities"`
		ComponentScope string `json:"component_scope"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AgentID != "agent-xyz" || resp.ComponentScope != "component:hello-agent" {
		t.Errorf("agent_id/component_scope = %q/%q", resp.AgentID, resp.ComponentScope)
	}
	if len(resp.Capabilities) != 1 || resp.Capabilities[0].Name != "can_invoke:tool:nmap" {
		t.Errorf("capabilities wire shape wrong: %+v", resp.Capabilities)
	}
	// Identity comes from the signed bootstrap claims, not the request body.
	if reg.gotTenant != "acme" || reg.gotOwner != "user-1" || reg.gotName != "hello-agent" || reg.gotBootstrapType != "bootstrap" {
		t.Errorf("registrar got tenant=%q owner=%q name=%q type=%q (name must be the signed claim, not body)",
			reg.gotTenant, reg.gotOwner, reg.gotName, reg.gotBootstrapType)
	}
	// The typed FGA principal threads from the signed claims into the agent
	// record so the per-kid descriptor can serve it (ADR-0045).
	if reg.gotPrincipal != "agent_principal:9" {
		t.Errorf("registrar got principal=%q, want the signed claim agent_principal:9", reg.gotPrincipal)
	}
}

func TestCGRegister_RejectsMissingBearer(t *testing.T) {
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{claims: &capabilitygrant.BootstrapClaims{}}, &fakeRegistrar{}, "https://api.test")
	rr := postRegister(t, h, "", validRegBody)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestCGRegister_RejectsBadBootstrap(t *testing.T) {
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{err: errExpiredForTest}, &fakeRegistrar{}, "https://api.test")
	rr := postRegister(t, h, "Bearer x.y.z", validRegBody)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestCGRegister_RejectsMissingKeys(t *testing.T) {
	h := capabilityGrantRegisterHandler(
		fakeBootstrapVerifier{claims: &capabilitygrant.BootstrapClaims{TenantID: "t", OwnerUserID: "o", PrincipalID: "p"}},
		&fakeRegistrar{},
		"https://api.test",
	)
	rr := postRegister(t, h, "Bearer x.y.z", `{"host_id":"h1","agent_name":"a"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing host/agent key)", rr.Code)
	}
}

func TestCGRegister_HostJWT_ReRegistration(t *testing.T) {
	reg := &fakeRegistrar{
		hostClaims: &capabilitygrant.HostClaims{
			HostID: "host-thumb", TenantID: "acme", OwnerUserID: "user-1", PrincipalRef: "agent_principal:9",
		},
		result: &capabilitygrant.RegisterCapabilityGrantResult{AgentID: "agent-new", ComponentScope: "component:hello"},
	}
	// The bootstrap verifier would FAIL — proving the host+jwt path is taken,
	// not the bootstrap path.
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{err: errExpiredForTest}, reg, "https://api.test")

	rr := postRegister(t, h, "Bearer "+hostJWTToken(), validRegBody)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	// Re-registration: identity comes from the host record; bootstrapType is
	// host_jwt; the name falls back to the request body (no signed claim).
	if reg.gotBootstrapType != "host_jwt" {
		t.Errorf("bootstrapType = %q, want host_jwt", reg.gotBootstrapType)
	}
	if reg.gotTenant != "acme" || reg.gotOwner != "user-1" || reg.gotPrincipal != "agent_principal:9" {
		t.Errorf("re-reg identity from host: tenant=%q owner=%q principal=%q", reg.gotTenant, reg.gotOwner, reg.gotPrincipal)
	}
	if reg.gotName != "body-name" {
		t.Errorf("re-reg name = %q, want the body name (no signed claim)", reg.gotName)
	}
	// The host+jwt audience the handler enforces is the register URL derived
	// from the public base URL.
	if reg.gotHostAud != "https://api.test/capabilitygrant/v1/register" {
		t.Errorf("host+jwt expected audience = %q", reg.gotHostAud)
	}
}

func TestCGRegister_HostJWT_RejectsInvalid(t *testing.T) {
	reg := &fakeRegistrar{hostErr: errExpiredForTest}
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{}, reg, "https://api.test")
	rr := postRegister(t, h, "Bearer "+hostJWTToken(), validRegBody)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (invalid host credential)", rr.Code)
	}
}

var errExpiredForTest = errTest("expired")

type errTest string

func (e errTest) Error() string { return string(e) }
