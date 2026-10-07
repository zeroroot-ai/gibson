// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

// TestCGSigningKeyDir_DefaultsToTheChartMount pins the default signing-key
// mount path used when the operator has not overridden it — must match the
// deploy chart's projected Secret mount point.
func TestCGSigningKeyDir_DefaultsToTheChartMount(t *testing.T) {
	t.Setenv("GIBSON_CGJWT_SIGNING_KEY_DIR", "")
	if got, want := cgSigningKeyDir(), "/etc/gibson/cg-signing-key"; got != want {
		t.Errorf("cgSigningKeyDir() = %q, want %q", got, want)
	}
}

// TestCGSigningKeyDir_HonoursOverride lets an operator relocate the mount
// (e.g. a non-default chart values override) without a code change.
func TestCGSigningKeyDir_HonoursOverride(t *testing.T) {
	t.Setenv("GIBSON_CGJWT_SIGNING_KEY_DIR", "/custom/cg-key")
	if got, want := cgSigningKeyDir(), "/custom/cg-key"; got != want {
		t.Errorf("cgSigningKeyDir() = %q, want %q", got, want)
	}
}

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
	gotCeiling                                                            []string
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
	capabilityCeiling []string,
) (*capabilitygrant.RegisterCapabilityGrantResult, error) {
	f.gotTenant, f.gotOwner, f.gotName, f.gotMode, f.gotPrincipal, f.gotBootstrapType = tenantID, ownerUserID, agentName, agentMode, principalRef, bootstrapType
	f.gotCeiling = capabilityCeiling
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
	h := capabilityGrantRegisterHandler(verifier, reg, nil, "https://api.test", nil)

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
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{claims: &capabilitygrant.BootstrapClaims{}}, &fakeRegistrar{}, nil, "https://api.test", nil)
	rr := postRegister(t, h, "", validRegBody)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestCGRegister_RejectsBadBootstrap(t *testing.T) {
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{err: errExpiredForTest}, &fakeRegistrar{}, nil, "https://api.test", nil)
	rr := postRegister(t, h, "Bearer x.y.z", validRegBody)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestCGRegister_RejectsMissingKeys(t *testing.T) {
	h := capabilityGrantRegisterHandler(
		fakeBootstrapVerifier{claims: &capabilitygrant.BootstrapClaims{TenantID: "t", OwnerUserID: "o", PrincipalID: "p"}},
		&fakeRegistrar{},
		nil,
		"https://api.test",
		nil,
	)
	rr := postRegister(t, h, "Bearer x.y.z", `{"host_id":"h1","agent_name":"a"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing host/agent key)", rr.Code)
	}
}

// reRegBody is a re-registration body that carries a real host key and the
// name that a caller may try to choose. It returns the body and the host id
// that the key has.
func reRegBody(t *testing.T, x, agentName string) (string, string) {
	t.Helper()
	jwk := json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}`)
	id, err := capabilitygrant.HostKeyID(jwk)
	if err != nil {
		t.Fatalf("HostKeyID: %v", err)
	}
	return `{"agent_name":"` + agentName + `","agent_mode":"autonomous","host_key_jwk":` + string(jwk) + `,"agent_key_jwk":{"kty":"OKP"}}`, id
}

func TestCGRegister_HostJWT_ReRegistration(t *testing.T) {
	body, hostID := reRegBody(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "body-name")
	reg := &fakeRegistrar{
		hostClaims: &capabilitygrant.HostClaims{
			HostID: hostID, TenantID: "acme", OwnerUserID: "user-1", PrincipalRef: "agent_principal:9",
			AgentName: "hello", CapabilityCeiling: []string{"execute:tool:nmap"},
		},
		result: &capabilitygrant.RegisterCapabilityGrantResult{AgentID: "agent-new", ComponentScope: "component:hello"},
	}
	// The bootstrap verifier would FAIL — proving the host+jwt path is taken,
	// not the bootstrap path.
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{err: errExpiredForTest}, reg, nil, "https://api.test", nil)

	rr := postRegister(t, h, "Bearer "+hostJWTToken(), body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	// Re-registration: identity comes from the host record; bootstrapType is
	// host_jwt.
	if reg.gotBootstrapType != "host_jwt" {
		t.Errorf("bootstrapType = %q, want host_jwt", reg.gotBootstrapType)
	}
	if reg.gotTenant != "acme" || reg.gotOwner != "user-1" || reg.gotPrincipal != "agent_principal:9" {
		t.Errorf("re-reg identity from host: tenant=%q owner=%q principal=%q", reg.gotTenant, reg.gotOwner, reg.gotPrincipal)
	}
	// The name and the ceiling are those of the enrolling credential. The
	// body name does not count.
	if reg.gotName != "hello" {
		t.Errorf("re-reg name = %q, want the stored name hello, not the body name", reg.gotName)
	}
	if len(reg.gotCeiling) != 1 || reg.gotCeiling[0] != "execute:tool:nmap" {
		t.Errorf("re-reg ceiling = %v, want the stored ceiling", reg.gotCeiling)
	}
	// The host+jwt audience the handler enforces is the register URL derived
	// from the public base URL.
	if reg.gotHostAud != "https://api.test/capabilitygrant/v1/register" {
		t.Errorf("host+jwt expected audience = %q", reg.gotHostAud)
	}
}

// A host key in the body that is not the host that signed the token adds a
// new host. The daemon refuses it, whatever the client does.
func TestCGRegister_HostJWT_RefusesAnotherHostKey(t *testing.T) {
	body, _ := reRegBody(t, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "hello")
	reg := &fakeRegistrar{hostClaims: &capabilitygrant.HostClaims{
		HostID: "the-host-that-signed", TenantID: "acme", OwnerUserID: "user-1", AgentName: "hello",
	}}
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{}, reg, nil, "https://api.test", nil)
	rr := postRegister(t, h, "Bearer "+hostJWTToken(), body)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if reg.gotTenant != "" {
		t.Fatal("a refused re-registration must not reach the registrar")
	}
}

// A host with no recorded agent name cannot re-register: the body must not
// supply one.
func TestCGRegister_HostJWT_RefusesAHostWithNoRecordedName(t *testing.T) {
	body, hostID := reRegBody(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "chosen-by-caller")
	reg := &fakeRegistrar{hostClaims: &capabilitygrant.HostClaims{HostID: hostID, TenantID: "acme", OwnerUserID: "user-1"}}
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{}, reg, nil, "https://api.test", nil)
	rr := postRegister(t, h, "Bearer "+hostJWTToken(), body)
	if rr.Code != http.StatusForbidden || reg.gotName != "" {
		t.Fatalf("status = %d, name = %q; want 403 and no registration", rr.Code, reg.gotName)
	}
}

func TestCGRegister_HostJWT_RejectsInvalid(t *testing.T) {
	reg := &fakeRegistrar{hostErr: errExpiredForTest}
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{}, reg, nil, "https://api.test", nil)
	rr := postRegister(t, h, "Bearer "+hostJWTToken(), validRegBody)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (invalid host credential)", rr.Code)
	}
}

var errExpiredForTest = errTest("expired")

type errTest string

func (e errTest) Error() string { return string(e) }
