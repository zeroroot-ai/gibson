// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

// fakePluginEnroller records how the register handler drives SVID enrollment.
type fakePluginEnroller struct {
	id        *pluginSVIDIdentity
	err       error
	called    bool
	gotToken  string
	gotRegURL string
}

func (f *fakePluginEnroller) ResolvePluginBySVID(_ context.Context, token, registerURL string) (*pluginSVIDIdentity, error) {
	f.called = true
	f.gotToken, f.gotRegURL = token, registerURL
	return f.id, f.err
}

// craftJWT builds a token whose JOSE header carries the given typ, so jwtTyp
// classifies it. Only the header is meaningful here — verification is faked.
func craftJWT(typ string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"` + typ + `"}`))
	return hdr + ".eyJzdWIiOiJ4In0.sig"
}

func TestPluginVendorFromSPIFFEID(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("zeroroot.ai")

	v, err := pluginVendorFromSPIFFEID(spiffeid.RequireFromPath(td, "/plugin/github"))
	if err != nil || v != "github" {
		t.Fatalf("valid plugin SVID: v=%q err=%v", v, err)
	}

	for _, bad := range []string{
		"/platform/daemon",   // not a plugin
		"/agent/foo",         // not a plugin
		"/plugin",            // no vendor subpath
		"/plugin/x",          // too short for the name rule
		"/plugin/Bad-Vendor", // uppercase not allowed
		"/plugin/a_b",        // underscore not allowed
	} {
		if _, err := pluginVendorFromSPIFFEID(spiffeid.RequireFromPath(td, bad)); err == nil {
			t.Errorf("SPIFFE path %q should be rejected as a plugin identity", bad)
		}
	}
}

// TestCGRegister_SVIDBranch: an SVID-typed token routes to the enroller, then
// through the shared RegisterCapabilityGrant path with bootstrapType spiffe_svid.
func TestCGRegister_SVIDBranch(t *testing.T) {
	enroller := &fakePluginEnroller{id: &pluginSVIDIdentity{
		TenantID: "acme", OwnerUserID: "owner-1", PrincipalRef: "plugin_principal:github", Name: "github",
	}}
	reg := &fakeRegistrar{result: &capabilitygrant.RegisterCapabilityGrantResult{
		AgentID: "agent-1", ComponentScope: "component:github",
	}}
	// The bootstrap verifier must NOT be consulted on the SVID path.
	verifier := fakeBootstrapVerifier{err: errors.New("bootstrap verifier must not be called for an SVID")}
	h := capabilityGrantRegisterHandler(verifier, reg, enroller, "https://api.test", nil)

	rr := postRegister(t, h, "Bearer "+craftJWT("JWT"), validRegBody)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	if !enroller.called {
		t.Fatal("SVID enroller was not invoked for an SVID-typed token")
	}
	if want := "https://api.test" + capabilityGrantRegisterPath; enroller.gotRegURL != want {
		t.Errorf("enroller registerURL = %q, want %q (the SVID audience)", enroller.gotRegURL, want)
	}
	if reg.gotBootstrapType != capabilitygrant.BootstrapTypeSPIFFESVID {
		t.Errorf("bootstrapType = %q, want %q", reg.gotBootstrapType, capabilitygrant.BootstrapTypeSPIFFESVID)
	}
	if reg.gotTenant != "acme" || reg.gotName != "github" || reg.gotPrincipal != "plugin_principal:github" {
		t.Errorf("identity from SVID wrong: tenant=%q name=%q principal=%q", reg.gotTenant, reg.gotName, reg.gotPrincipal)
	}
}

// TestCGRegister_BootstrapNotStolenBySVIDBranch: a bootstrap-typed token goes to
// the bootstrap path even when the SVID enroller is wired.
func TestCGRegister_BootstrapNotStolenBySVIDBranch(t *testing.T) {
	enroller := &fakePluginEnroller{id: &pluginSVIDIdentity{}}
	verifier := fakeBootstrapVerifier{claims: &capabilitygrant.BootstrapClaims{
		TenantID: "acme", OwnerUserID: "u", PrincipalID: "agent_principal:1", Name: "a",
	}}
	reg := &fakeRegistrar{result: &capabilitygrant.RegisterCapabilityGrantResult{AgentID: "x", ComponentScope: "component:a"}}
	h := capabilityGrantRegisterHandler(verifier, reg, enroller, "https://api.test", nil)

	rr := postRegister(t, h, "Bearer "+craftJWT(capabilitygrant.BootstrapTokenType), validRegBody)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rr.Code)
	}
	if enroller.called {
		t.Error("bootstrap-typed token was routed to the SVID enroller — it must take the bootstrap path")
	}
	if reg.gotBootstrapType != "bootstrap" {
		t.Errorf("bootstrapType = %q, want bootstrap", reg.gotBootstrapType)
	}
}

// TestCGRegister_SVIDUnverified401: an unverifiable SVID answers 401, not 500.
func TestCGRegister_SVIDUnverified401(t *testing.T) {
	enroller := &fakePluginEnroller{err: ErrSVIDUnverified}
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{}, &fakeRegistrar{}, enroller, "https://api.test", nil)
	rr := postRegister(t, h, "Bearer "+craftJWT("JWT"), validRegBody)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
}

// TestCGRegister_SVIDProvisionError500: a verified SVID whose provisioning
// fails is an internal error (500), distinguishable from an auth failure.
func TestCGRegister_SVIDProvisionError500(t *testing.T) {
	enroller := &fakePluginEnroller{err: errors.New("fga write failed")}
	h := capabilityGrantRegisterHandler(fakeBootstrapVerifier{}, &fakeRegistrar{}, enroller, "https://api.test", nil)
	rr := postRegister(t, h, "Bearer "+craftJWT("JWT"), validRegBody)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
}

// --- ResolvePluginBySVID: real JWT-SVID verification against a SPIRE bundle ---

type fakeProvisioner struct {
	gotVendor, gotTenant string
	ref                  string
	err                  error
}

// ProvisionPluginPrincipal resolves the owner itself in production; the fake
// returns a fixed "owner-1" so the enroller's identity carries it.
func (f *fakeProvisioner) ProvisionPluginPrincipal(_ context.Context, vendor, tenantID string) (principalRef, ownerUserID string, err error) {
	f.gotVendor, f.gotTenant = vendor, tenantID
	if f.err != nil {
		return "", "", f.err
	}
	ref := f.ref
	if ref == "" {
		ref = "plugin_principal:" + vendor
	}
	return ref, "owner-1", nil
}

// mintTestJWTSVID signs a JWT-SVID (sub=SPIFFE ID, aud, exp) with an ECDSA P-256 key (ES256)
// whose public half is registered in the bundle under kid, so
// jwtsvid.ParseAndValidate accepts it.
func mintTestJWTSVID(t *testing.T, priv *ecdsa.PrivateKey, kid string, id spiffeid.ID, aud string, exp time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject:  id.String(),
		Audience: jwt.Audience{aud},
		Expiry:   jwt.NewNumericDate(exp),
	}).Serialize()
	if err != nil {
		t.Fatalf("sign JWT-SVID: %v", err)
	}
	return token
}

func TestResolvePluginBySVID(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("zeroroot.ai")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := jwtbundle.New(td)
	if err := bundle.AddJWTAuthority("k1", priv.Public()); err != nil {
		t.Fatal(err)
	}

	const registerURL = "https://api.test/capabilitygrant/v1/register"
	pluginID := spiffeid.RequireFromPath(td, "/plugin/github")

	newEnroller := func(prov *fakeProvisioner) *spiffePluginEnroller {
		return &spiffePluginEnroller{
			bundles:     bundle,
			trustDomain: td,
			cg:          prov,
			tenantID:    "acme",
			logger:      slog.Default(),
		}
	}

	t.Run("happy path", func(t *testing.T) {
		prov := &fakeProvisioner{}
		e := newEnroller(prov)
		token := mintTestJWTSVID(t, priv, "k1", pluginID, registerURL, time.Now().Add(time.Hour))
		id, err := e.ResolvePluginBySVID(context.Background(), token, registerURL)
		if err != nil {
			t.Fatalf("ResolvePluginBySVID: %v", err)
		}
		if id.Name != "github" || id.PrincipalRef != "plugin_principal:github" || id.TenantID != "acme" || id.OwnerUserID != "owner-1" {
			t.Errorf("identity = %+v", id)
		}
		if prov.gotVendor != "github" || prov.gotTenant != "acme" {
			t.Errorf("provisioner got vendor=%q tenant=%q", prov.gotVendor, prov.gotTenant)
		}
	})

	t.Run("wrong audience is unverified", func(t *testing.T) {
		e := newEnroller(&fakeProvisioner{})
		token := mintTestJWTSVID(t, priv, "k1", pluginID, "https://evil.example/register", time.Now().Add(time.Hour))
		if _, err := e.ResolvePluginBySVID(context.Background(), token, registerURL); !errors.Is(err, ErrSVIDUnverified) {
			t.Errorf("err = %v, want ErrSVIDUnverified", err)
		}
	})

	t.Run("expired is unverified", func(t *testing.T) {
		e := newEnroller(&fakeProvisioner{})
		token := mintTestJWTSVID(t, priv, "k1", pluginID, registerURL, time.Now().Add(-time.Hour))
		if _, err := e.ResolvePluginBySVID(context.Background(), token, registerURL); !errors.Is(err, ErrSVIDUnverified) {
			t.Errorf("err = %v, want ErrSVIDUnverified", err)
		}
	})

	t.Run("unknown signing key is unverified", func(t *testing.T) {
		otherPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		e := newEnroller(&fakeProvisioner{})
		token := mintTestJWTSVID(t, otherPriv, "k1", pluginID, registerURL, time.Now().Add(time.Hour))
		if _, err := e.ResolvePluginBySVID(context.Background(), token, registerURL); !errors.Is(err, ErrSVIDUnverified) {
			t.Errorf("err = %v, want ErrSVIDUnverified", err)
		}
	})

	t.Run("non-plugin SPIFFE ID is unverified", func(t *testing.T) {
		e := newEnroller(&fakeProvisioner{})
		daemonID := spiffeid.RequireFromPath(td, "/platform/daemon")
		token := mintTestJWTSVID(t, priv, "k1", daemonID, registerURL, time.Now().Add(time.Hour))
		if _, err := e.ResolvePluginBySVID(context.Background(), token, registerURL); !errors.Is(err, ErrSVIDUnverified) {
			t.Errorf("err = %v, want ErrSVIDUnverified", err)
		}
	})

	t.Run("SVID trust domain != configured is unverified", func(t *testing.T) {
		// The SVID parses (its own TD's bundle is found), but the enroller is
		// pinned to a different trust domain, so the post-parse TD check rejects it.
		e := newEnroller(&fakeProvisioner{})
		e.trustDomain = spiffeid.RequireTrustDomainFromString("other.example")
		token := mintTestJWTSVID(t, priv, "k1", pluginID, registerURL, time.Now().Add(time.Hour))
		if _, err := e.ResolvePluginBySVID(context.Background(), token, registerURL); !errors.Is(err, ErrSVIDUnverified) {
			t.Errorf("err = %v, want ErrSVIDUnverified", err)
		}
	})

	t.Run("provisioning failure surfaces (not unverified)", func(t *testing.T) {
		e := newEnroller(&fakeProvisioner{err: errors.New("fga down")})
		token := mintTestJWTSVID(t, priv, "k1", pluginID, registerURL, time.Now().Add(time.Hour))
		_, err := e.ResolvePluginBySVID(context.Background(), token, registerURL)
		if err == nil || errors.Is(err, ErrSVIDUnverified) {
			t.Errorf("err = %v, want a non-ErrSVIDUnverified error", err)
		}
	})
}
