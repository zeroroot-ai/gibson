// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

// Login shapes — how an agent that drives a vendor model authenticates to that
// vendor (ADR-0019 decision 4). The Claude Code terms name exactly these
// credential routes and forbid a host from removing any of them, so the set is
// closed and lives next to the manifest that declares the credentials for each.
const (
	// LoginShapeAPIKey is the vendor's own API key, held in the tenant's
	// provider configuration. It is the default when a launch names no shape,
	// because a one-shot dispatch has no person present to sign in.
	LoginShapeAPIKey = "api_key"
	// LoginShapeSubscription is a person's own subscription. The platform
	// stores nothing: the person signs in inside the sandbox, in the
	// unmodified vendor binary, through the vendor's own flow. So this shape
	// injects no model credential at all.
	LoginShapeSubscription = "subscription"
	// LoginShapeBedrock, LoginShapeVertex and LoginShapeFoundry are the three
	// third-party inference routes, each funded by the tenant's own account
	// with that provider.
	LoginShapeBedrock = "bedrock"
	LoginShapeVertex  = "vertex"
	LoginShapeFoundry = "foundry"
)

// loginShapeFlags is the environment a shape sets on its own, beyond the
// credentials the manifest names. Claude Code reads these to pick the inference
// route; a shape with no flag needs none.
var loginShapeFlags = map[string]map[string]string{
	LoginShapeAPIKey:       {},
	LoginShapeSubscription: {},
	LoginShapeBedrock:      {"CLAUDE_CODE_USE_BEDROCK": "1"},
	LoginShapeVertex:       {"CLAUDE_CODE_USE_VERTEX": "1"},
	LoginShapeFoundry:      {"CLAUDE_CODE_USE_FOUNDRY": "1"},
}

// IsLoginShape reports whether s names a login shape.
func IsLoginShape(s string) bool {
	_, ok := loginShapeFlags[s]
	return ok
}

// LoginShapes returns every login shape, for an error message that tells an
// author what the valid values are.
func LoginShapes() []string {
	return []string{
		LoginShapeAPIKey,
		LoginShapeSubscription,
		LoginShapeBedrock,
		LoginShapeVertex,
		LoginShapeFoundry,
	}
}

// LoginShapeFlags returns the environment shape sets on its own. The returned
// map is a copy, so a caller cannot edit the table.
func LoginShapeFlags(shape string) map[string]string {
	out := make(map[string]string, len(loginShapeFlags[shape]))
	for k, v := range loginShapeFlags[shape] {
		out[k] = v
	}
	return out
}
