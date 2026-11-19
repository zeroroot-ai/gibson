// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"net"
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
