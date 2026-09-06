// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — secrets_plugin_associations.go
//
// FGASecretsPluginAssociations is the production SecretsAdminPluginAssociations:
// it answers "which plugin principals can resolve this secret?" by reading the
// can_resolve FGA tuples written by PluginsAdminServer.
package admin

import (
	"context"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/sdk/auth"
)

// FGASecretsPluginAssociations resolves plugin principals bound to a secret via
// the can_resolve relation. The can_resolve tuples are written by
// PluginsAdminServer with:
//
//	User:     "plugin_principal:<install_id>"
//	Relation: "can_resolve"
//	Object:   "secret:tenant-<tenant>/<callerName>"
//
// (tenant-id and ref joined with "/", never ":" — gibson#1024, authz.TenantQualifiedSep)
//
// so the reverse lookup is ListUsersOfType(objectType="secret",
// object="secret:tenant-<tenant>/<callerName>", relation="can_resolve",
// userType="plugin_principal").
//
// The subject type is plugin_principal, NOT user. model.fga declares
// `can_resolve: [plugin_principal]` and that restriction is the structural gate
// of spec non-plugin-secret-isolation — a user-typed can_resolve tuple cannot
// exist. This reader used to ask for "user", which OpenFGA answers with an
// empty list and no error, so it reported "no plugin can resolve this secret"
// for every secret. authz.ListUsers now refuses that query outright rather than
// answering it emptily.
type FGASecretsPluginAssociations struct {
	authorizer authz.Authorizer
}

// NewFGASecretsPluginAssociations constructs the production associations reader.
func NewFGASecretsPluginAssociations(authorizer authz.Authorizer) *FGASecretsPluginAssociations {
	return &FGASecretsPluginAssociations{authorizer: authorizer}
}

// PluginsBoundTo returns the principal IDs holding can_resolve on the secret.
// secretName arrives in stored form (colon-flat at the KV root, e.g.
// "cred:openai"); with that layout the stored key equals the caller-facing
// ref, so callerName is an identity normaliser here.
func (f *FGASecretsPluginAssociations) PluginsBoundTo(ctx context.Context, tenant auth.TenantID, secretName string) ([]string, error) {
	if f.authorizer == nil {
		return nil, nil
	}
	ref := callerName(secretName)
	object := fmt.Sprintf("secret:tenant-%s/%s", tenant, ref)
	users, err := f.authorizer.ListUsersOfType(ctx, "secret", object, "can_resolve", "plugin_principal")
	if err != nil {
		return nil, fmt.Errorf("secrets admin: list can_resolve principals for %q: %w", object, err)
	}
	out := make([]string, 0, len(users))
	for _, u := range users {
		// Refs come back fully qualified as "plugin_principal:<id>".
		out = append(out, strings.TrimPrefix(u, "plugin_principal:"))
	}
	return out, nil
}
