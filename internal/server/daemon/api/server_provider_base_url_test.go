// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"google.golang.org/grpc/status"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

func baseURLInput(baseURL string) *tenantv1.ProviderConfigInput {
	in := anthropicSaveInput("claude-x", 64000)
	in.Credentials = map[string]string{"api_key": "k", fieldBaseURL: baseURL}
	return in
}

// A save refuses a base_url whose host has an internal address or does not
// resolve, and saves nothing.
func TestSaveProvider_RefusesAnInternalBaseURL(t *testing.T) {
	resolver := fakeOutsideResolver{
		"metadata.example": {net.ParseIP("169.254.169.254")},
		"cluster.example":  {net.ParseIP("10.0.0.7")},
		"mixed.example":    {net.ParseIP("93.184.216.34"), net.ParseIP("127.0.0.1")},
	}
	for _, raw := range []string{
		"https://metadata.example/v1",
		"https://cluster.example:8443/v1",
		"https://mixed.example",
		"https://127.0.0.1/v1",
		"http://[::1]:11434",
		"https://unknown.example/v1",
		"https:///v1",
		"://bad",
	} {
		t.Run(raw, func(t *testing.T) {
			store := &mockProviderStore{createOut: fakeProviderRecord("p"), updateOut: fakeProviderRecord("p")}
			s := serverWithStore(t, store)
			s.modelEndpointResolver = resolver

			_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: baseURLInput(raw)})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, grpcCode(err))
			assert.Nil(t, store.capturedCreateInput, "nothing is saved")
			assertNoAddressDetail(t, err)

			_, err = s.UpdateProvider(tenantCtx("acme"), &tenantv1.UpdateProviderRequest{
				Name: "p", Input: baseURLInput(raw),
			})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, grpcCode(err))
			assert.Nil(t, store.capturedUpdateInput, "nothing is saved")
		})
	}
}

// A base_url of a public host is saved. A provider with no base_url needs no
// lookup.
func TestSaveProvider_AcceptsAPublicBaseURL(t *testing.T) {
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := serverWithStore(t, store)
	s.modelEndpointResolver = fakeOutsideResolver{"api.example": {net.ParseIP("93.184.216.34")}}

	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: baseURLInput("https://api.example/v1"),
	})
	require.NoError(t, err)
	require.NotNil(t, store.capturedCreateInput)

	store2 := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s2 := serverWithStore(t, store2)
	s2.modelEndpointResolver = fakeOutsideResolver{}
	_, err = s2.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: anthropicSaveInput("claude-x", 64000),
	})
	require.NoError(t, err)
}

// security.allow_private_llm_endpoints lets an in-cluster model server through.
func TestSaveProvider_AllowPrivateModelEndpointsSkipsTheAddressCheck(t *testing.T) {
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := serverWithStore(t, store)
	s.modelEndpointResolver = fakeOutsideResolver{"cluster.example": {net.ParseIP("10.0.0.7")}}
	s.WithPrivateModelEndpoints(true)

	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: baseURLInput("https://cluster.example:8443/v1"),
	})
	require.NoError(t, err)
	require.NotNil(t, store.capturedCreateInput)
}

// NewDaemonServer gives the check a resolver, so the check never meets a nil
// resolver.
func TestNewDaemonServer_HasTheModelEndpointResolver(t *testing.T) {
	s := NewDaemonServer(nil, nil, nil)
	assert.Equal(t, net.DefaultResolver, s.modelEndpointResolver)
	assert.False(t, s.allowPrivateModelEndpoints)
}

// A provider that the gateway routes needs a base_url that the ModelProvider
// CRD accepts. Without this rule the save passes, the CRD refuses the record,
// and the provider never reconciles with no error to the user. The rule holds
// with allow_private_llm_endpoints set.
func TestSaveProvider_RefusesABaseURLThatTheCRDRefuses(t *testing.T) {
	resolver := fakeOutsideResolver{"api.example": {net.ParseIP("93.184.216.34")}}
	for _, allowPrivate := range []bool{false, true} {
		for _, raw := range []string{
			"http://api.example/v1",
			"https://user:pw@api.example/v1",
			"https://api.example/v1?key=x",
			"https://api.example/v1#frag",
			"https://api.example/v1?",
		} {
			store := &mockProviderStore{createOut: fakeProviderRecord("p")}
			s := serverWithStore(t, store)
			s.modelEndpointResolver = resolver
			s.WithPrivateModelEndpoints(allowPrivate)
			_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: baseURLInput(raw)})
			require.Error(t, err, "%s (allow private %v)", raw, allowPrivate)
			assert.Equal(t, codes.InvalidArgument, grpcCode(err))
			assert.Contains(t, err.Error(), "must be an https URL")
			assert.Nil(t, store.capturedCreateInput, "nothing is saved")
		}
	}
	// A path is allowed, as the CRD allows it.
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := serverWithStore(t, store)
	s.modelEndpointResolver = resolver
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: baseURLInput("https://api.example:8443/inference/v1"),
	})
	require.NoError(t, err)
}

// A type that the gateway does not route never becomes a ModelProvider, so the
// CRD shape does not apply to it. The address check still does.
func TestSaveProvider_AnUnroutedTypeKeepsItsURLShape(t *testing.T) {
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := serverWithStore(t, store)
	s.modelEndpointResolver = fakeOutsideResolver{"ollama.example": {net.ParseIP("93.184.216.34")}}
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: &tenantv1.ProviderConfigInput{
		Name: "local", Type: "ollama", DefaultModel: "m", DefaultModelContextWindow: 8192,
		Credentials: map[string]string{fieldBaseURL: "http://ollama.example:11434"},
	}})
	require.NoError(t, err)
}

// The pattern of the save is the pattern of the CRD.
func TestModelProviderBaseURLPattern_IsThePatternOfTheCRD(t *testing.T) {
	crd, err := os.ReadFile(filepath.Join("..", "..", "..", "..",
		"operators", "tenant", "config", "crd", "bases", "gibson.zeroroot.ai_modelproviders.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(crd), "pattern: "+modelProviderBaseURLPattern.String())
}

// assertNoAddressDetail checks that an error for the client names no IP address, no
// address class and no resolver. The detail goes to the daemon log.
func assertNoAddressDetail(t *testing.T, err error) {
	t.Helper()
	text := status.Convert(err).Message()
	assert.NotRegexp(t, `\d+\.\d+\.\d+\.\d+|::1`, text, "no IP address")
	for _, word := range []string{"private address", "loopback", "link-local", "carrier-grade", "netguard", "lookup", "no such host", ":53"} {
		assert.NotContains(t, text, word)
	}
}
