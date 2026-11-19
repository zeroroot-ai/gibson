// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/cabundle"
	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// testCABundle returns a PEM bundle with one self-signed CA certificate.
func testCABundle(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestRegisterOutsideAgent_ChecksTheCABundleAtSaveTime(t *testing.T) {
	bundle := testCABundle(t)
	cases := map[string]struct {
		secrets map[string][]byte
		want    codes.Code
	}{
		"a bundle":          {map[string][]byte{"partner-ca": bundle}, codes.OK},
		"a missing secret":  {map[string][]byte{}, codes.InvalidArgument},
		"not a certificate": {map[string][]byte{"partner-ca": []byte("hello")}, codes.InvalidArgument},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newOutsideFixture(t)
			f.secrets.data = c.secrets
			resp, err := f.svc.RegisterOutsideAgent(f.ctx, &tenantv1.RegisterOutsideAgentRequest{
				Name: "partner-scout", A2AUrl: outsideURL, CaBundleSecret: "partner-ca"})
			if c.want == codes.OK {
				require.NoError(t, err)
				assert.Equal(t, "partner-ca", resp.GetEntry().GetCaBundleSecret())
				assert.Equal(t, "partner-ca", f.store.entries["partner-scout"].CABundleSecret)
				return
			}
			require.Error(t, err)
			assert.Equal(t, c.want, status.Code(err))
			assert.Empty(t, f.store.entries, "a refused record was stored")
			assert.Empty(t, f.fga.writtenTuples(), "a refused record wrote a tuple")
		})
	}
}

func TestRegisterOutsideAgent_NoCABundleReadsNoSecret(t *testing.T) {
	f := newOutsideFixture(t)
	_, err := f.svc.RegisterOutsideAgent(f.ctx, reg("partner-scout", outsideURL))
	require.NoError(t, err)
	assert.Empty(t, f.secrets.tenants, "the service read a secret for a record with no CA bundle")
}

func TestGetOutsideAgentCredential_AddsTheCABundle(t *testing.T) {
	bundle := testCABundle(t)
	store := &tenantOutsideStore{byTenant: map[string][]outsideagentstore.Entry{
		"acme": {
			{Name: "both", CredentialSecret: "key", CABundleSecret: "ca"},
			{Name: "ca-only", CABundleSecret: "ca"},
			{Name: "bad-ca", CABundleSecret: "key"},
		},
	}}
	secrets := &fakeCredStore{data: map[string][]byte{"key": []byte("tok"), "ca": bundle}}
	srv := outsideOperatorServer(store, secrets)
	get := func(name string) (*daemonoperatorv1.GetOutsideAgentCredentialResponse, error) {
		return srv.GetOutsideAgentCredential(peerCtx(t, testTenantOperatorSVID),
			&daemonoperatorv1.GetOutsideAgentCredentialRequest{TenantId: "acme", Name: name})
	}

	resp, err := get("both")
	require.NoError(t, err)
	assert.Equal(t, "tok", string(resp.GetData()[OutsideAgentCredentialKey]))
	assert.Equal(t, bundle, resp.GetData()[cabundle.Key])

	resp, err = get("ca-only")
	require.NoError(t, err)
	assert.Len(t, resp.GetData(), 1)
	assert.Equal(t, bundle, resp.GetData()[cabundle.Key])

	_, err = get("bad-ca")
	assert.Equal(t, codes.NotFound, status.Code(err), "a secret that holds no certificate must not reach the gateway")
}

func TestGetModelProviderCredential_AddsTheCABundle(t *testing.T) {
	bundle := testCABundle(t)
	store := &fakeCredStore{data: map[string][]byte{
		"provider_cred:mock:api_key": []byte("sk-mock"), "mock-ca": bundle, "not-ca": []byte("hello"),
	}}
	srv := modelCredServer(store)
	req := modelCredReq("openai-compatible", "provider_cred:mock")

	req.CaBundleSecret = "mock-ca"
	resp, err := srv.GetModelProviderCredential(peerCtx(t, testTenantOperatorSVID), req)
	require.NoError(t, err)
	assert.Equal(t, "sk-mock", string(resp.GetData()[ModelCredentialKeyAuthorization]))
	assert.Equal(t, bundle, resp.GetData()[cabundle.Key])

	for _, bad := range []string{"not-ca", "missing"} {
		req.CaBundleSecret = bad
		_, err = srv.GetModelProviderCredential(peerCtx(t, testTenantOperatorSVID), req)
		assert.Equal(t, codes.NotFound, status.Code(err), bad)
	}

	req.CaBundleSecret = ""
	resp, err = srv.GetModelProviderCredential(peerCtx(t, testTenantOperatorSVID), req)
	require.NoError(t, err)
	assert.NotContains(t, resp.GetData(), cabundle.Key)
}

func TestCheckProviderCABundle(t *testing.T) {
	bundle := testCABundle(t)
	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	input := func(creds map[string]string) *tenantv1.ProviderConfigInput {
		return &tenantv1.ProviderConfigInput{Credentials: creds}
	}
	srv := newPendingServer().WithModelProviderCredentialSource(
		&fakeCredStore{data: map[string][]byte{"ca": bundle, "not-ca": []byte("x")}}, testTenantOperatorSVID)

	assert.NoError(t, srv.checkProviderCABundle(tctx, input(nil)), "no field")
	assert.NoError(t, srv.checkProviderCABundle(tctx, input(map[string]string{cabundle.Field: " "})), "blank field")
	assert.NoError(t, srv.checkProviderCABundle(tctx, input(map[string]string{cabundle.Field: "ca"})))
	assert.Error(t, srv.checkProviderCABundle(tctx, input(map[string]string{cabundle.Field: "not-ca"})))
	assert.Error(t, srv.checkProviderCABundle(tctx, input(map[string]string{cabundle.Field: "missing"})))
	assert.Error(t, newPendingServer().checkProviderCABundle(tctx, input(map[string]string{cabundle.Field: "ca"})),
		"no secret store")
}
