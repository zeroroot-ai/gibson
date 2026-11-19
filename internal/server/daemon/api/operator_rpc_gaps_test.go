// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/cabundle"
	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

func TestGatewayProviderType_MapsEachRecordType(t *testing.T) {
	tests := []struct {
		in       providerconfig.ProviderType
		want     string
		wantSkip bool
	}{
		{providerconfig.ProviderAnthropic, gatewayTypeAnthropic, false},
		{providerconfig.ProviderOpenAI, gatewayTypeOpenAI, false},
		{providerconfig.ProviderOpenAICompatible, gatewayTypeOpenAICompatible, false},
		{providerconfig.ProviderBedrock, gatewayTypeBedrock, false},
		{providerconfig.ProviderGoogle, gatewayTypeGemini, false},
		{providerconfig.ProviderVertex, gatewayTypeVertexAI, false},
		{providerconfig.ProviderVoyage, "", true},
		{providerconfig.ProviderType("odd"), "", true},
	}
	for _, tt := range tests {
		got, skip := gatewayProviderType(tt.in)
		assert.Equal(t, tt.want, got, "type %q", tt.in)
		assert.Equal(t, tt.wantSkip, skip != "", "type %q", tt.in)
	}
}

// errProviders is a provider store whose list call fails.
type errProviders struct {
	providerConfigStoreIface
	err error
}

func (e errProviders) List(context.Context, string) ([]*providerconfig.ProviderConfig, error) {
	return nil, e.err
}

func TestGetTenantModelProviders_RefusalsAndShapes(t *testing.T) {
	ctx := peerCtx(t, testTenantOperatorSVID)
	req := &daemonoperatorv1.GetTenantModelProvidersRequest{TenantId: "acme"}

	_, err := newPendingServer().GetTenantModelProviders(ctx, req)
	assert.Equal(t, codes.Unavailable, status.Code(err), "an unwired daemon")

	srv := modelCredServer(&fakeCredStore{})
	srv.providerConfig = errProviders{err: errors.New("db down")}
	_, err = srv.GetTenantModelProviders(ctx, req)
	assert.Equal(t, codes.Internal, status.Code(err), "the list fails")

	srv.providerConfig = fakeProviders{}
	_, err = srv.GetTenantModelProviders(ctx, &daemonoperatorv1.GetTenantModelProvidersRequest{TenantId: "Not A Tenant"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a bad tenant id")

	store := &fakeCredStore{data: map[string][]byte{
		"provider_cred:gv:region":     []byte(" us-east5 "),
		"provider_cred:gv:project_id": []byte("proj-1"),
	}}
	srv = modelCredServer(store)
	srv.providerConfig = fakeProviders{records: []*providerconfig.ProviderConfig{
		nil,
		{Name: "off", Type: providerconfig.ProviderOpenAI, Enabled: false},
		{Name: "gv", Type: providerconfig.ProviderVertex, Enabled: true},
		{Name: "vo", Type: providerconfig.ProviderVoyage, Enabled: true},
	}}
	resp, err := srv.GetTenantModelProviders(ctx, req)
	require.NoError(t, err)
	require.Len(t, resp.GetProviders(), 1, "a disabled record and a nil record are left out")
	assert.Equal(t, "us-east5", resp.GetProviders()[0].GetRegion(), "the value is trimmed")
	assert.Equal(t, "proj-1", resp.GetProviders()[0].GetProjectId())
	require.Len(t, resp.GetSkipped(), 1)
	assert.Contains(t, resp.GetSkipped()[0], "vo: voyage is not a provider type")
}

func TestOperatorRPCs_ABadTenantIdIsInvalid(t *testing.T) {
	ctx := peerCtx(t, testTenantOperatorSVID)
	srv := outsideOperatorServer(&tenantOutsideStore{}, &fakeCredStore{})
	_, err := srv.GetTenantOutsideAgents(ctx, &daemonoperatorv1.GetTenantOutsideAgentsRequest{TenantId: "Not A Tenant"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = srv.GetOutsideAgentCredential(ctx,
		&daemonoperatorv1.GetOutsideAgentCredentialRequest{TenantId: "Not A Tenant", Name: "scout"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	cred := modelCredServer(&fakeCredStore{})
	_, err = cred.GetModelProviderCredential(ctx, &daemonoperatorv1.GetModelProviderCredentialRequest{
		TenantId: "Not A Tenant", CredentialSecret: "provider_cred:x", ProviderType: "anthropic",
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetOutsideAgentCredential_StoreFailureAndEmptySecret(t *testing.T) {
	ctx := peerCtx(t, testTenantOperatorSVID)
	req := &daemonoperatorv1.GetOutsideAgentCredentialRequest{TenantId: "acme", Name: "scout"}

	broken := outsideOperatorServer(&tenantOutsideStore{err: errors.New("db down")}, &fakeCredStore{})
	_, err := broken.GetOutsideAgentCredential(ctx, req)
	assert.Equal(t, codes.Internal, status.Code(err))

	store := &tenantOutsideStore{byTenant: map[string][]outsideagentstore.Entry{
		"acme": {{Name: "scout", CredentialSecret: "scout-key"}},
	}}
	empty := outsideOperatorServer(store, &fakeCredStore{data: map[string][]byte{"cred:scout-key": {}}})
	_, err = empty.GetOutsideAgentCredential(ctx, req)
	require.Equal(t, codes.NotFound, status.Code(err))
	assert.Contains(t, err.Error(), "is empty")
}

func TestGetModelProviderCredential_ARefusedCABundleIsNotFound(t *testing.T) {
	store := &fakeCredStore{data: map[string][]byte{"provider_cred:claude:api_key": []byte("sk")}}
	_, err := modelCredServer(store).GetModelProviderCredential(peerCtx(t, testTenantOperatorSVID),
		&daemonoperatorv1.GetModelProviderCredentialRequest{
			TenantId: "acme", CredentialSecret: "provider_cred:claude", ProviderType: "anthropic",
			CaBundleSecret: "missing-ca",
		})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestGetModelProviderCredential_AnIncompleteBedrockCredentialFails(t *testing.T) {
	store := &fakeCredStore{data: map[string][]byte{
		"provider_cred:eu:aws_access_key_id":     []byte("AKIA"),
		"provider_cred:eu:aws_secret_access_key": {},
	}}
	_, err := modelCredServer(store).GetModelProviderCredential(peerCtx(t, testTenantOperatorSVID),
		&daemonoperatorv1.GetModelProviderCredentialRequest{
			TenantId: "acme", CredentialSecret: "provider_cred:eu", ProviderType: "bedrock",
		})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestToGRPCProviderError_NameAndCredentialRefusalsAreInvalidArgument(t *testing.T) {
	assert.Equal(t, codes.InvalidArgument, grpcCode(toGRPCProviderError("op", providerconfig.ErrInvalidName)))
	assert.Equal(t, codes.InvalidArgument, grpcCode(toGRPCProviderError("op", providerconfig.ErrInvalidCredentials)))
}

func TestProviderMutations_ACABundleThatCannotBeCheckedIsInvalid(t *testing.T) {
	input := &tenantv1.ProviderConfigInput{
		Name: "p", Type: "openai", Credentials: map[string]string{cabundle.Field: "my-ca", "api_key": "k"},
	}
	// No tenant secret store is wired, so the bundle cannot be checked.
	s := serverWithStore(t, &mockProviderStore{})
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: input})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err), "create")
	_, err = s.UpdateProvider(tenantCtx("acme"), &tenantv1.UpdateProviderRequest{Name: "p", Input: input})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err), "update")

	// A store is wired and does not hold the secret.
	s.modelCredStore = &fakeCredStore{}
	_, err = s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: input})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err), "create with a missing secret")
}

func TestSpanAttributes_ReadsEachValueType(t *testing.T) {
	kv := func(key string, v *commonpb.AnyValue) *commonpb.KeyValue {
		return &commonpb.KeyValue{Key: key, Value: v}
	}
	got := spanAttributes([]*commonpb.KeyValue{
		kv("s", &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "x"}}),
		kv("i", &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 7}}),
		kv("d", &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: 1.5}}),
		kv("b", &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: true}}),
		kv("bytes", &commonpb.AnyValue{Value: &commonpb.AnyValue_BytesValue{BytesValue: []byte("z")}}),
	})
	assert.Equal(t, map[string]any{"s": "x", "i": int64(7), "d": 1.5, "b": true}, got, "a bytes value is left out")
}
