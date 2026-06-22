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
}
