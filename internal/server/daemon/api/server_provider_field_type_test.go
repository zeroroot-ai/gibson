// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// TestEveryCredentialFieldHasAType fails when a provider descriptor field
// reaches the dashboard with no type (gibson#701).
func TestEveryCredentialFieldHasAType(t *testing.T) {
	s := blankServer()
	resp, err := s.GetSupportedProviders(tenantCtx("acme"), &tenantv1.GetSupportedProvidersRequest{})
	require.NoError(t, err)
	fields := 0
	for _, p := range resp.GetProviders() {
		for _, f := range p.GetCredentials() {
			fields++
			if f.GetType() == tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_UNSPECIFIED {
				t.Errorf("provider %s, field %s: no type", p.GetType(), f.GetKey())
			}
			if f.GetSecret() && f.GetType() != tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_PASSWORD {
				t.Errorf("provider %s, field %s: a secret field must be PASSWORD, got %v", p.GetType(), f.GetKey(), f.GetType())
			}
		}
	}
	require.Positive(t, fields, "the catalogue has no credential field, so this test would prove nothing")
}

// The mapping gives UNSPECIFIED for a kind it does not know, so the test
// above can fail.
func TestCredentialFieldTypeToProto(t *testing.T) {
	for kind, want := range map[providerconfig.CredentialFieldType]tenantv1.CredentialFieldType{
		providerconfig.FieldText:     tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_TEXT,
		providerconfig.FieldPassword: tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_PASSWORD,
		providerconfig.FieldURL:      tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_URL,
		providerconfig.FieldRegion:   tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_REGION,
		providerconfig.FieldBool:     tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_BOOL,
		"":                           tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_UNSPECIFIED,
		"color":                      tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_UNSPECIFIED,
	} {
		require.Equal(t, want, credentialFieldTypeToProto(kind), "kind %q", kind)
	}
}

// GetSupportedProviders lists each provider type with its credential fields.
func TestGetSupportedProviders_ListsEachProviderWithItsFields(t *testing.T) {
	s := blankServer()
	resp, err := s.GetSupportedProviders(tenantCtx("acme"), &tenantv1.GetSupportedProvidersRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetProviders())
	for _, p := range resp.GetProviders() {
		require.NotEmpty(t, p.GetType(), "each provider has a type")
	}
}

// A call with no tenant in its context is refused.
func TestGetSupportedProviders_RequiresATenant(t *testing.T) {
	s := blankServer()
	_, err := s.GetSupportedProviders(context.Background(), &tenantv1.GetSupportedProvidersRequest{})
	require.Error(t, err)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}
