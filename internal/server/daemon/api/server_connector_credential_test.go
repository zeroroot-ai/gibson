// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/connectorauth"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	testConnectorOperatorSVID = "spiffe://install.example/platform/connector-operator"
	testTenantOperatorSVID    = "spiffe://install.example/platform/tenant-operator"
	testEdgeSVID              = "spiffe://install.example/platform/envoy"
	testVendorValue           = "vendor-access-token-do-not-log"
)

var credNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// fakeCredStore is a tenant connector secret store keyed by secret name. It
// records the tenant of each read.
type fakeCredStore struct {
	data    map[string][]byte
	err     error
	tenants []string
}

func (s *fakeCredStore) Resolve(ctx context.Context, name string) ([]byte, error) {
	if t, ok := auth.TenantFromContext(ctx); ok {
		s.tenants = append(s.tenants, t.String())
	}
	if s.err != nil {
		return nil, s.err
	}
	v, ok := s.data[name]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return append([]byte(nil), v...), nil
}

func credMeta(t *testing.T, offset time.Duration) []byte {
	t.Helper()
	// Only the expiry is set; the token field stays empty.
	b, err := json.Marshal(connectorauth.AccessToken{ExpiresAt: credNow.Add(offset)}) //nolint:gosec // G117: no secret value
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func liveTokenStore(t *testing.T) *fakeCredStore {
	t.Helper()
	return &fakeCredStore{data: map[string][]byte{
		connectorauth.AccessMetaSecretName("gitlab"): credMeta(t, time.Hour),
		connectorauth.AccessSecretName("gitlab"):     []byte(testVendorValue),
	}}
}

// peerCtx is a context whose TLS peer certificate carries the SPIFFE ID svid.
// An empty svid gives a TLS peer with no SPIFFE ID.
func peerCtx(t *testing.T, svid string) context.Context {
	t.Helper()
	cert := &x509.Certificate{}
	if svid != "" {
		u, err := url.Parse(svid)
		if err != nil {
			t.Fatal(err)
		}
		cert.URIs = []*url.URL{u}
	}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}},
	})
}

func credServer(store ConnectorSecretResolver) *DaemonServer {
	srv := newPendingServer()
	srv.WithConnectorCredentialSource(store, testConnectorOperatorSVID)
	srv.connectorCredNow = func() time.Time { return credNow }
	return srv
}

func gitlabCredReq() *daemonoperatorv1.GetConnectorCredentialRequest {
	return &daemonoperatorv1.GetConnectorCredentialRequest{TenantId: "acme", ConnectorId: "gitlab"}
}

// Only the direct-dial connector operator gets the credential. A call through
// the edge arrives with the TLS peer of Envoy, also when it carries a
// platform_operator token, and it is refused. So is a call from a different
// operator, a call with no SPIFFE ID and a call with no TLS peer.
func TestGetConnectorCredential_OnlyTheConnectorOperator(t *testing.T) {
	srv := credServer(liveTokenStore(t))

	refused := map[string]context.Context{
		"through the edge with a platform_operator token": auth.WithIdentity(peerCtx(t, testEdgeSVID), auth.Identity{
			Subject: "platform-admin", CredentialType: auth.CredentialType("client-credentials"),
		}),
		"another operator SVID":         peerCtx(t, testTenantOperatorSVID),
		"a TLS peer with no SPIFFE ID":  peerCtx(t, ""),
		"no TLS peer":                   context.Background(),
		"a SPIFFE ID in another domain": peerCtx(t, "spiffe://other.example/platform/connector-operator"),
	}
	for name, ctx := range refused {
		t.Run(name, func(t *testing.T) {
			resp, err := srv.GetConnectorCredential(ctx, gitlabCredReq())
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
			}
			if resp != nil {
				t.Fatal("a refused call got a response")
			}
		})
	}

	resp, err := srv.GetConnectorCredential(peerCtx(t, testConnectorOperatorSVID), gitlabCredReq())
	if err != nil {
		t.Fatalf("the connector operator was refused: %v", err)
	}
	if got := string(resp.GetData()["authorization"]); got != "Bearer "+testVendorValue {
		t.Fatalf("authorization = %q", got)
	}
}

// The response holds the access token and the declared credentials, and no
// other key: never a refresh token or a Grant.
func TestGetConnectorCredential_ReturnsOnlyTheSecretContent(t *testing.T) {
	store := liveTokenStore(t)
	store.data[connectorauth.GrantSecretName("gitlab")] = []byte(`{"refresh_token":"never-returned"}`)
	store.data["gitlab-pat"] = []byte(`{"token":"static-value"}`)
	srv := credServer(store)

	req := gitlabCredReq()
	req.Credentials = []*daemonoperatorv1.ConnectorCredentialRef{{Key: "gitlab-pat", Property: "token", TargetEnv: "GITLAB_PAT"}}
	resp, err := srv.GetConnectorCredential(peerCtx(t, testConnectorOperatorSVID), req)
	if err != nil {
		t.Fatalf("GetConnectorCredential: %v", err)
	}
	if len(resp.GetData()) != 2 || string(resp.GetData()["GITLAB_PAT"]) != "static-value" {
		t.Fatalf("data keys = %v, want authorization and GITLAB_PAT", keysOf(resp.GetData()))
	}
	for k, v := range resp.GetData() {
		if bytes.Contains(v, []byte("never-returned")) {
			t.Fatalf("key %s holds Grant material", k)
		}
	}
	for _, tenant := range store.tenants {
		if tenant != "acme" {
			t.Fatalf("a read used the tenant %q, want acme", tenant)
		}
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A token past its expiry is withheld, and with nothing else declared the
// operator is told to withdraw the Secret.
func TestGetConnectorCredential_ExpiredTokenIsWithdrawn(t *testing.T) {
	store := liveTokenStore(t)
	store.data[connectorauth.AccessMetaSecretName("gitlab")] = credMeta(t, -time.Minute)
	resp, err := credServer(store).GetConnectorCredential(peerCtx(t, testConnectorOperatorSVID), gitlabCredReq())
	if err != nil {
		t.Fatalf("GetConnectorCredential: %v", err)
	}
	if !resp.GetWithdraw() || len(resp.GetData()) != 0 {
		t.Fatalf("withdraw = %v, data = %v; want withdraw and no data", resp.GetWithdraw(), keysOf(resp.GetData()))
	}
}

// Nothing minted and nothing declared is an empty answer, not an error.
func TestGetConnectorCredential_NothingMinted(t *testing.T) {
	resp, err := credServer(&fakeCredStore{}).GetConnectorCredential(peerCtx(t, testConnectorOperatorSVID), gitlabCredReq())
	if err != nil {
		t.Fatalf("GetConnectorCredential: %v", err)
	}
	if resp.GetWithdraw() || len(resp.GetData()) != 0 {
		t.Fatalf("withdraw = %v, data = %v; want an empty answer", resp.GetWithdraw(), keysOf(resp.GetData()))
	}
}

// A store failure, a corrupt metadata blob and a missing property are errors.
// No error text and no log line holds the token or a credential value.
func TestGetConnectorCredential_ErrorsCarryNoSecret(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := peerCtx(t, testConnectorOperatorSVID)
	cases := map[string]struct {
		store *fakeCredStore
		req   *daemonoperatorv1.GetConnectorCredentialRequest
	}{
		"store down": {store: &fakeCredStore{err: errors.New("broker down")}, req: gitlabCredReq()},
		"corrupt metadata": {store: &fakeCredStore{data: map[string][]byte{
			connectorauth.AccessMetaSecretName("gitlab"): []byte("{not json " + testVendorValue),
		}}, req: gitlabCredReq()},
		"missing property": {store: func() *fakeCredStore {
			s := liveTokenStore(t)
			s.data["gitlab-pat"] = []byte(`{"other":"static-value"}`)
			return s
		}(), req: &daemonoperatorv1.GetConnectorCredentialRequest{
			TenantId: "acme", ConnectorId: "gitlab",
			Credentials: []*daemonoperatorv1.ConnectorCredentialRef{{Key: "gitlab-pat", Property: "token", TargetEnv: "GITLAB_PAT"}},
		}},
		"property of a value that is not JSON": {store: func() *fakeCredStore {
			s := liveTokenStore(t)
			s.data["gitlab-pat"] = []byte("plain static-value")
			return s
		}(), req: &daemonoperatorv1.GetConnectorCredentialRequest{
			TenantId: "acme", ConnectorId: "gitlab",
			Credentials: []*daemonoperatorv1.ConnectorCredentialRef{{Key: "gitlab-pat", Property: "token", TargetEnv: "GITLAB_PAT"}},
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := credServer(c.store).GetConnectorCredential(ctx, c.req)
			if status.Code(err) != codes.Internal {
				t.Fatalf("code = %v, want Internal", status.Code(err))
			}
			for _, secret := range []string{testVendorValue, "static-value"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("the error holds a secret: %v", err)
				}
			}
		})
	}
	for _, secret := range []string{testVendorValue, "static-value"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("the log holds a secret:\n%s", logs.String())
		}
	}
}

func TestGetConnectorCredential_BadRequests(t *testing.T) {
	srv := credServer(liveTokenStore(t))
	ctx := peerCtx(t, testConnectorOperatorSVID)
	for _, req := range []*daemonoperatorv1.GetConnectorCredentialRequest{
		{ConnectorId: "gitlab"},
		{TenantId: "acme"},
		{TenantId: "Not A Tenant", ConnectorId: "gitlab"},
	} {
		if _, err := srv.GetConnectorCredential(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("request %v: code %v, want InvalidArgument", req, status.Code(err))
		}
	}
	unwired := newPendingServer()
	if _, err := unwired.GetConnectorCredential(ctx, gitlabCredReq()); status.Code(err) != codes.Unavailable {
		t.Errorf("unwired: code %v, want Unavailable", status.Code(err))
	}
}

// failOnName is a secret store that fails the read of one name only.
type failOnName struct {
	*fakeCredStore
	name string
}

func (s failOnName) Resolve(ctx context.Context, name string) ([]byte, error) {
	if name == s.name {
		return nil, errors.New("broker down")
	}
	return s.fakeCredStore.Resolve(ctx, name)
}

// The reader keys each answer on the secrets it reads: a missing or empty
// token gives no header, a failed read is an error, and a declared
// credential is served raw, as a JSON string or as raw JSON.
func TestConnectorCredentialReader_Read(t *testing.T) {
	ref := func(key, property string) []*daemonoperatorv1.ConnectorCredentialRef {
		return []*daemonoperatorv1.ConnectorCredentialRef{{Key: key, Property: property, TargetEnv: "STATIC"}}
	}
	withData := func(extra map[string][]byte) *fakeCredStore {
		s := liveTokenStore(t)
		for k, v := range extra {
			s.data[k] = v
		}
		return s
	}
	now := func() time.Time { return credNow }
	cases := map[string]struct {
		store   ConnectorSecretResolver
		refs    []*daemonoperatorv1.ConnectorCredentialRef
		want    map[string]string
		wantErr bool
	}{
		"empty metadata": {
			store: &fakeCredStore{data: map[string][]byte{connectorauth.AccessMetaSecretName("gitlab"): {}}},
		},
		"metadata but no token": {
			store: &fakeCredStore{data: map[string][]byte{connectorauth.AccessMetaSecretName("gitlab"): credMeta(t, time.Hour)}},
		},
		"empty token": {
			store: withData(map[string][]byte{connectorauth.AccessSecretName("gitlab"): {}}),
		},
		"token read fails": {
			store:   failOnName{fakeCredStore: liveTokenStore(t), name: connectorauth.AccessSecretName("gitlab")},
			wantErr: true,
		},
		"credential with no target env": {
			store:   liveTokenStore(t),
			refs:    []*daemonoperatorv1.ConnectorCredentialRef{{Key: "gitlab-pat"}},
			wantErr: true,
		},
		"credential not found": {store: liveTokenStore(t), refs: ref("gitlab-pat", ""), wantErr: true},
		"raw credential": {
			store: withData(map[string][]byte{"gitlab-pat": []byte("raw-value")}),
			refs:  ref("gitlab-pat", ""),
			want:  map[string]string{connectorCredSecretKey: "Bearer " + testVendorValue, "STATIC": "raw-value"},
		},
		"property that is not a string": {
			store: withData(map[string][]byte{"gitlab-pat": []byte(`{"port":8443}`)}),
			refs:  ref("gitlab-pat", "port"),
			want:  map[string]string{connectorCredSecretKey: "Bearer " + testVendorValue, "STATIC": "8443"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			data, withdraw, err := connectorCredentialReader{secrets: c.store, now: now}.read(context.Background(), "gitlab", c.refs)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, c.wantErr)
			}
			if withdraw {
				t.Fatal("withdraw = true, want false")
			}
			if len(data) != len(c.want) {
				t.Fatalf("data keys = %v, want %d keys", keysOf(data), len(c.want))
			}
			for k, v := range c.want {
				if string(data[k]) != v {
					t.Errorf("data[%s] = %q, want %q", k, data[k], v)
				}
			}
		})
	}
}

// With no clock set, the reader measures expiry on the wall clock.
func TestConnectorCredentialReader_DefaultClock(t *testing.T) {
	before := time.Now()
	if got := (connectorCredentialReader{}).clock(); got.Before(before) {
		t.Fatalf("clock = %v, want a time after %v", got, before)
	}
}
