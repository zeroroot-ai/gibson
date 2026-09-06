// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/cgjwt"
	"github.com/zeroroot-ai/sdk/capabilitygrant"
)

// The per-kid key endpoint hands ext-authz the document that says which key
// signs for which FGA principal. Whoever answers that fetch therefore decides
// who every caller is, so the fetch is SPIFFE mTLS pinned to the daemon's SVID
// — the same treatment the authz-registry fetch gets (GHSA-8m76-9r77-xvh3).
//
// These tests exercise the pin from both sides. Each refusal is paired with an
// acceptance over the identical descriptor bytes, so no assertion here can be
// satisfied by the fetch simply not happening.

const (
	testTrustDomain  = "zeroroot.ai"
	testDaemonSVID   = "spiffe://" + testTrustDomain + "/platform/daemon"
	testImpostorSVID = "spiffe://" + testTrustDomain + "/ns/gibson/sa/impostor"
	testExtAuthzSVID = "spiffe://" + testTrustDomain + "/ns/gibson/sa/gibson-ext-authz"

	testKeysPathPrefix = "/capabilitygrant/v1/keys/"
	testKid            = "agent-1"
	testPrincipal      = "agent_principal:9"
	testTenant         = "acme"
	testRPCMethod      = "/gibson.component.v1.ComponentService/SubmitFinding"
)

// startKeyEndpoint runs the daemon's per-kid key endpoint over mTLS, presenting
// serverSource's SVID and requiring a client cert its bundle trusts. It returns
// the base URL for ComponentConfig.KeysBaseURL.
//
// It deliberately does not use httptest.StartTLS: that injects its own
// certificate into tls.Config.Certificates, which the handshake prefers over
// the SPIFFE GetCertificate callback when the client dials an IP (no SNI), so
// the peer identity under test would silently not be the one served.
func startKeyEndpoint(t *testing.T, serverSource *staticSource, authorizedClients ...spiffeid.ID) string {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc(testKeysPathPrefix, func(w http.ResponseWriter, r *http.Request) {
		kid := strings.TrimPrefix(r.URL.Path, testKeysPathPrefix)
		if kid != testKid {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(descriptorJSON(t, kid))
	})

	authorizer := tlsconfig.AuthorizeAny()
	if len(authorizedClients) > 0 {
		authorizer = tlsconfig.AuthorizeOneOf(authorizedClients...)
	}
	tlsCfg := tlsconfig.MTLSServerConfig(serverSource, serverSource, authorizer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(tls.NewListener(ln, tlsCfg)) }()
	t.Cleanup(func() { _ = srv.Close() })

	return "https://" + ln.Addr().String() + "/capabilitygrant/v1/keys"
}

// descriptorJSON is the component key document: the JWK plus the daemon's
// assertion of who that key belongs to. Every peer in these tests serves the
// same bytes, so acceptance and refusal can only turn on who served them.
var testDescriptorPub ed25519.PublicKey
var testDescriptorPriv ed25519.PrivateKey

func init() {
	var err error
	testDescriptorPub, testDescriptorPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
}

func descriptorJSON(t *testing.T, kid string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"keys": []any{map[string]any{
			"kty": "OKP", "crv": "Ed25519", "kid": kid,
			"x": base64.RawURLEncoding.EncodeToString(testDescriptorPub),
		}},
		"principal": testPrincipal,
		"tenant":    testTenant,
		"status":    "active",
	})
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	return b
}

func mintComponentToken(t *testing.T, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"sub":    kid,
		"aud":    capabilitygrant.AudienceGibsonDaemon,
		"iat":    time.Now().Add(-time.Second).Unix(),
		"exp":    time.Now().Add(55 * time.Second).Unix(),
		"jti":    fmt.Sprintf("jti-%d", time.Now().UnixNano()),
		"method": testRPCMethod,
	})
	tok.Header["typ"] = "agent+jwt"
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(testDescriptorPriv)
	if err != nil {
		t.Fatalf("sign component token: %v", err)
	}
	return signed
}

// verifierAgainst wires the production path end to end — the same
// buildCGVerifiers call main makes — and returns the component verifier
// ext-authz would run.
func verifierAgainst(t *testing.T, keysURL string, clientSource *staticSource) *cgjwt.ComponentVerifier {
	t.Helper()
	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", keysURL)
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", testDaemonSVID)
	t.Setenv("EXT_AUTHZ_CGJWT_ISSUER", "https://api.zeroroot.ai")

	dispatch, component, err := buildCGVerifiers(discardLogger(), clientSource, clientSource)
	if err != nil {
		t.Fatalf("buildCGVerifiers: %v", err)
	}
	// Both verifiers resolve keys from this endpoint, so both must be wired.
	if dispatch == nil {
		t.Fatal("buildCGVerifiers returned no dispatch verifier despite the keys URL being set")
	}
	if component == nil {
		t.Fatal("buildCGVerifiers returned no component verifier despite the keys URL being set")
	}
	return component
}

// TestCGVerifiers_DisabledTogether — with no keys URL there is no key endpoint,
// so neither verifier is built. They are enabled and disabled as one because
// they share the one fetch-by-kid path (ADR-0045).
func TestCGVerifiers_DisabledTogether(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "")
	dispatch, component, err := buildCGVerifiers(discardLogger(), extAuthz, extAuthz)
	if err != nil {
		t.Fatalf("buildCGVerifiers with the keys URL unset: %v", err)
	}
	if dispatch != nil || component != nil {
		t.Fatalf("verifiers built despite the keys URL being unset: dispatch=%v component=%v", dispatch, component)
	}
}

// TestCGVerifiers_PropagateTransportFailure — a bad keys URL must stop startup
// at the verifier wiring, not be swallowed into a verifier that quietly cannot
// fetch.
func TestCGVerifiers_PropagateTransportFailure(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "http://gibson:8085/capabilitygrant/v1/keys")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", testDaemonSVID)

	if _, _, err := buildCGVerifiers(discardLogger(), extAuthz, extAuthz); err == nil {
		t.Fatal("buildCGVerifiers accepted a plaintext keys URL")
	}
}

// TestCGVerifiers_PropagateDispatchFailure — a misconfigured dispatch verifier
// (no pinned issuer) must stop startup too. Both verifiers hang off the same
// key endpoint, so neither may be quietly skipped when the other is fine.
func TestCGVerifiers_PropagateDispatchFailure(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "https://gibson:8086/capabilitygrant/v1/keys")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", testDaemonSVID)
	t.Setenv("EXT_AUTHZ_CGJWT_ISSUER", "")

	_, _, err := buildCGVerifiers(discardLogger(), extAuthz, extAuthz)
	if err == nil {
		t.Fatal("buildCGVerifiers accepted a dispatch verifier with no pinned issuer")
	}
	if !strings.Contains(err.Error(), "EXT_AUTHZ_CGJWT_ISSUER") {
		t.Fatalf("err = %v, want it to name the missing variable", err)
	}
}

// TestCGKeysClient_UnparseableURLRefused — a keys URL that is not a URL at all
// fails startup on the same path as a plaintext one, rather than reaching the
// fetch as a malformed target.
func TestCGKeysClient_UnparseableURLRefused(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "https://gibson:8086/\x7f/keys")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", testDaemonSVID)

	client, err := buildCGKeysClient(discardLogger(), extAuthz, extAuthz)
	if err == nil {
		t.Fatalf("buildCGKeysClient = %v, nil — an unparseable keys URL must fail startup", client)
	}
	if !strings.Contains(err.Error(), "EXT_AUTHZ_CGJWT_KEYS_URL") {
		t.Fatalf("err = %v, want it to name the variable", err)
	}
}

// TestCGKeys_DaemonPeerAccepted is the positive half of every pin assertion
// below. Without it, a refusal proves nothing: a verifier that never fetches
// anything also refuses everything.
func TestCGKeys_DaemonPeerAccepted(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	daemon := newStaticSource(t, ca, mustSPIFFEID(t, testDaemonSVID), ca)
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	keysURL := startKeyEndpoint(t, daemon, mustSPIFFEID(t, testExtAuthzSVID))
	v := verifierAgainst(t, keysURL, extAuthz)

	id, err := v.Verify(context.Background(), mintComponentToken(t, testKid), testRPCMethod)
	if err != nil {
		t.Fatalf("Verify against the real daemon peer: %v", err)
	}
	if id.Principal != testPrincipal || id.Tenant != testTenant {
		t.Fatalf("identity = %+v, want principal %q tenant %q", id, testPrincipal, testTenant)
	}
}

// TestCGKeys_SameTrustDomainNonDaemonPeerRefused is the load-bearing case.
//
// The peer here is not an outsider. It holds a genuine SVID, issued by the
// same platform CA, for a real path in the zeroroot.ai trust domain — the
// posture of any other workload on the pod network. It serves byte-identical
// descriptor bytes to the ones the daemon serves in the test above, which
// passes. The only difference is which SPIFFE ID answered.
//
// A test that instead swapped the CA would pass against a client that merely
// validated the chain and never checked the identity — a half-fix. This one
// fails against that client.
func TestCGKeys_SameTrustDomainNonDaemonPeerRefused(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	impostor := newStaticSource(t, ca, mustSPIFFEID(t, testImpostorSVID), ca)
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	keysURL := startKeyEndpoint(t, impostor, mustSPIFFEID(t, testExtAuthzSVID))
	v := verifierAgainst(t, keysURL, extAuthz)

	_, err := v.Verify(context.Background(), mintComponentToken(t, testKid), testRPCMethod)
	if err == nil {
		t.Fatal("descriptor accepted from a peer that is not the daemon; the SVID pin is not enforced")
	}
	if !errors.Is(err, cgjwt.ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey (the descriptor fetch must fail)", err)
	}
	if !strings.Contains(err.Error(), testImpostorSVID) {
		t.Fatalf("err = %v, want it to name the rejected peer %s", err, testImpostorSVID)
	}
}

// TestCGKeys_ForeignCAPeerRefused pairs with the case above: the peer claims
// the daemon's exact SPIFFE ID but its SVID chains to an authority outside the
// trust bundle. The two together separate "chain is valid" from "identity is
// the daemon"; either check alone leaves one of them open.
//
// The rogue endpoint trusts ext-authz's CA, so the client cert it receives is
// acceptable and the handshake fails specifically on the server identity.
func TestCGKeys_ForeignCAPeerRefused(t *testing.T) {
	platformCA := newTestCA(t, "zeroroot-platform-ca")
	foreignCA := newTestCA(t, "attacker-ca")

	// Foreign-signed SVID, daemon's own ID; trusts the platform CA for clients.
	rogue := newStaticSource(t, foreignCA, mustSPIFFEID(t, testDaemonSVID), platformCA)
	extAuthz := newStaticSource(t, platformCA, mustSPIFFEID(t, testExtAuthzSVID), platformCA)

	keysURL := startKeyEndpoint(t, rogue, mustSPIFFEID(t, testExtAuthzSVID))
	v := verifierAgainst(t, keysURL, extAuthz)

	_, err := v.Verify(context.Background(), mintComponentToken(t, testKid), testRPCMethod)
	if err == nil {
		t.Fatal("descriptor accepted from a peer whose SVID chains outside the trust bundle")
	}
	if !errors.Is(err, cgjwt.ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey (the descriptor fetch must fail)", err)
	}
}

// TestCGKeysClient_PlaintextURLRefused — a plaintext keys URL must stop
// startup, not downgrade the fetch.
//
// This is not a stylistic preference. http.Transport applies TLSClientConfig
// only to https:// URLs, so a plaintext URL handed to the pinned client would
// fetch in the clear with no error anywhere — the exact silent-plaintext
// outcome the pin exists to remove. There is no scheme-conditional branch and
// no opt-out flag, so this cannot decay into the permanent state.
func TestCGKeysClient_PlaintextURLRefused(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "http://gibson:8085/capabilitygrant/v1/keys")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", testDaemonSVID)

	client, err := buildCGKeysClient(discardLogger(), extAuthz, extAuthz)
	if err == nil {
		t.Fatalf("buildCGKeysClient = %v, nil — a plaintext keys URL must fail startup", client)
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v, want it to name the https requirement", err)
	}
	if !strings.Contains(err.Error(), "8086") {
		t.Fatalf("err = %v, want it to name the mTLS listener the chart must point at", err)
	}
}

// TestCGKeysClient_RequiresDaemonSVID — an https keys URL with no pin is not a
// weaker configuration that still works; it is no pin at all, so it is refused.
func TestCGKeysClient_RequiresDaemonSVID(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "https://gibson:8086/capabilitygrant/v1/keys")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", "")

	if _, err := buildCGKeysClient(discardLogger(), extAuthz, extAuthz); err == nil {
		t.Fatal("buildCGKeysClient accepted an https keys URL with no daemon SVID to pin")
	} else if !strings.Contains(err.Error(), "EXT_AUTHZ_DAEMON_SVID") {
		t.Fatalf("err = %v, want it to name the missing variable", err)
	}
}

// TestCGKeysClient_DisabledWhenKeysURLUnset — with no keys URL there is
// nothing to fetch and both verifiers are off, so the transport is absent
// rather than an error.
func TestCGKeysClient_DisabledWhenKeysURLUnset(t *testing.T) {
	ca := newTestCA(t, "zeroroot-platform-ca")
	extAuthz := newStaticSource(t, ca, mustSPIFFEID(t, testExtAuthzSVID), ca)

	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "")
	client, err := buildCGKeysClient(discardLogger(), extAuthz, extAuthz)
	if err != nil {
		t.Fatalf("buildCGKeysClient with the keys URL unset: %v", err)
	}
	if client != nil {
		t.Fatal("buildCGKeysClient returned a transport despite the keys URL being unset")
	}
}

// TestVerifiersRefuseUnpinnedTransport — the wiring cannot silently fall back
// to a default client if a future edit drops the plumbing: with the keys URL
// set, both verifier constructors refuse a nil transport.
func TestVerifiersRefuseUnpinnedTransport(t *testing.T) {
	t.Setenv("EXT_AUTHZ_CGJWT_KEYS_URL", "https://gibson:8086/capabilitygrant/v1/keys")
	t.Setenv("EXT_AUTHZ_CGJWT_ISSUER", "https://api.zeroroot.ai")

	if v, err := buildComponentVerifier(discardLogger(), nil); err == nil {
		t.Fatalf("buildComponentVerifier = %v, nil — a nil transport must not be defaulted", v)
	}
	if v, err := buildCGVerifier(discardLogger(), nil); err == nil {
		t.Fatalf("buildCGVerifier = %v, nil — a nil transport must not be defaulted", v)
	}
}
