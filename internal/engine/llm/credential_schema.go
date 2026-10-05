// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llm

// CredentialField describes a single credential input for a provider type.
// Providers expose a slice of these via CredentialSchema() so the daemon's
// GetSupportedProviders RPC can hand the dashboard a machine-readable form
// spec — no hard-coded frontend dropdowns, no drift between daemon and UI.
type CredentialField struct {
	// Key is the cfg.Extra map key the resolver will read. For the canonical
	// fields APIKey and BaseURL, use "api_key" / "base_url" — the daemon
	// handler maps those back to the typed ProviderConfig fields.
	Key string

	// Label is the human-facing form label.
	Label string

	// Required flags the field as mandatory for successful construction.
	Required bool

	// Secret tells the dashboard to render a password input and mask in logs.
	Secret bool

	// Placeholder is an example value shown in the empty input.
	Placeholder string

	// Help is a short description rendered beneath the field.
	Help string

	// Type is the input kind of the field (gibson#701). Each field sets one;
	// TestEveryCredentialFieldHasAType fails on a field with none.
	Type CredentialFieldType
}

// CredentialFieldType is the input kind of a credential field. The daemon
// maps it to the CredentialFieldType enum of the provider proto, so the
// dashboard builds its form from it.
type CredentialFieldType string

// The input kinds of a credential field.
const (
	FieldText     CredentialFieldType = "text"
	FieldPassword CredentialFieldType = "password"
	FieldURL      CredentialFieldType = "url"
	FieldRegion   CredentialFieldType = "region"
	FieldBool     CredentialFieldType = "bool"
)
