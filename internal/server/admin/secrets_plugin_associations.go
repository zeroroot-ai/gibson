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
//	User:     "user:<principal>"
//	Relation: "can_resolve"
//	Object:   "secret:tenant-<tenant>/<callerName>"
//
// (tenant-id and ref joined with "/", never ":" — gibson#1024, authz.TenantQualifiedSep)
//
// so the reverse lookup is ListUsers(objectType="secret",
// object="secret:tenant-<tenant>/<callerName>", relation="can_resolve").
type FGASecretsPluginAssociations struct {
	authorizer authz.Authorizer
}

// NewFGASecretsPluginAssociations constructs the production associations reader.
func NewFGASecretsPluginAssociations(authorizer authz.Authorizer) *FGASecretsPluginAssociations {
	return &FGASecretsPluginAssociations{authorizer: authorizer}
}

// PluginsBoundTo returns the principal IDs holding can_resolve on the secret.
// secretName arrives in stored form (e.g. "user/cred:openai"); the can_resolve
// object uses the caller-facing ref, so it is normalised via callerName before
// building the FGA object.
func (f *FGASecretsPluginAssociations) PluginsBoundTo(ctx context.Context, tenant auth.TenantID, secretName string) ([]string, error) {
	if f.authorizer == nil {
		return nil, nil
	}
	ref := callerName(secretName)
	object := fmt.Sprintf("secret:tenant-%s/%s", tenant, ref)
	users, err := f.authorizer.ListUsers(ctx, "secret", object, "can_resolve")
	if err != nil {
		return nil, fmt.Errorf("secrets admin: list can_resolve users for %q: %w", object, err)
	}
	out := make([]string, 0, len(users))
	for _, u := range users {
		// FGA user refs are "user:<principal>"; strip the type prefix.
		out = append(out, strings.TrimPrefix(u, "user:"))
	}
	return out, nil
}
