// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package secrets

import (
	"strings"

	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
)

// CategoryPrefix returns the colon-flat key prefix of a secret category. It
// returns an empty string for a category with no prefix.
func CategoryPrefix(cat secretsv1.SecretCategory) string {
	switch cat {
	case secretsv1.SecretCategory_SECRET_CATEGORY_CRED:
		return "cred:"
	case secretsv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG:
		return "provider_config:"
	default:
		return ""
	}
}

// StoredName returns the broker key of a tenant secret. Tenant secrets are
// stored colon-flat at the root as "<category>:<name>". A name that already has
// the prefix is returned as it is. SetSecret and each reader of a secret that a
// user names (for example ca_bundle_secret) use this one rule.
func StoredName(cat secretsv1.SecretCategory, name string) string {
	prefix := CategoryPrefix(cat)
	if prefix == "" || strings.HasPrefix(name, prefix) {
		return name
	}
	return prefix + name
}
