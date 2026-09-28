// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
)

// The IdP username of a machine principal is `<role>-<tenant>-<name>`. The
// prefix keeps usernames unique across the shared IdP org. It is a naming
// convention, never an isolation boundary: FGA scopes every listing. Both
// directions of the convention live here, so a reader can never drift from
// the writer.

// serviceAccountName builds the IdP username CreateAgentIdentity registers.
func serviceAccountName(role idp.Role, tenantID, name string) string {
	return string(role) + "-" + tenantID + "-" + name
}

// identityName recovers the name the person gave from the IdP username. An
// account whose username does not carry this tenant's prefix keeps its
// username as its name, so nothing is hidden.
func identityName(role idp.Role, tenantID, username string) string {
	return strings.TrimPrefix(username, serviceAccountName(role, tenantID, ""))
}
