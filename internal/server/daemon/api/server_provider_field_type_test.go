// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
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
	for kind, want := range map[llm.CredentialFieldType]tenantv1.CredentialFieldType{
		llm.FieldText:     tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_TEXT,
		llm.FieldPassword: tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_PASSWORD,
		llm.FieldURL:      tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_URL,
		llm.FieldRegion:   tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_REGION,
		llm.FieldBool:     tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_BOOL,
		"":                tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_UNSPECIFIED,
		"color":           tenantv1.CredentialFieldType_CREDENTIAL_FIELD_TYPE_UNSPECIFIED,
	} {
		require.Equal(t, want, credentialFieldTypeToProto(kind), "kind %q", kind)
	}
}
