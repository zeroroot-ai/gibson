// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Plugin invocation grant helpers per spec plugin-runtime Phase 10 (Task 25).
//
// These helpers write the FGA tuple that grants every member of a tenant
// (which includes every tool_principal scoped to that tenant) the right to
// invoke a registered plugin. The PluginInvoke RPC's authz annotation
// (`tenant_and_field('PluginName')`) resolves the FGA object at request
// time to `plugin:<tenant_id>:<plugin_name>` (see
// core/ext-authz/internal/fga/check.go:resolveObject), so the tuple's object
// must use the same shape.
//
// Tuple shape:
//
//	(tenant:<tenant_id>#member, can_invoke, plugin:<tenant_id>:<plugin_name>)
//
// v1 simplification: only this single tenant-wide grant is written. Per-tool
// granular grants of the shape (tool_principal:<id>, can_invoke,
// plugin:<tenant_id>:<plugin_name>) are out of scope; the FGA model accepts
// the tool_principal direct grant so they can be added later without a
// model change.
//
// agent_principal is intentionally excluded: agents dispatch tools, tools
// invoke plugins (per Requirement 5.2). The plugin type's can_invoke list
// does not include agent_principal, so agents are structurally barred from
// invoking plugins.
package fga

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// PluginCanInvokeTuple returns the FGA tuple that grants every tenant member
// can_invoke on the registered plugin.
//
// Tuple shape:
//
//	(tenant:<tenantID>#member, can_invoke, plugin:<tenantID>:<pluginName>)
//
// The object ID must match what the PluginInvoke RPC's
// `tenant_and_field('PluginName')` deriver produces at check time:
// `plugin:<tenantID>:<pluginName>`.
//
// Callers are responsible for gating on PrincipalKind==plugin before
// invoking; tool/agent enrollments do not produce a plugin object and
// therefore receive no can_invoke tuple.
func PluginCanInvokeTuple(pluginName, tenantID string) Tuple {
	return Tuple{
		User:     fmt.Sprintf("tenant:%s#member", tenantID),
		Relation: "can_invoke",
		Object:   fmt.Sprintf("plugin:%s/%s", tenantID, pluginName),
	}
}

// WritePluginCanInvokeGrant writes the can_invoke FGA tuple for a registered
// plugin. Idempotent: if the tuple already exists, the function returns nil
// (ErrAlreadyExists is treated as success).
//
// This must only be called for plugin_principal enrollments. Callers are
// responsible for gating on PrincipalKind==plugin before invoking.
func WritePluginCanInvokeGrant(ctx context.Context, fgaClient Client, pluginName, tenantID string) error {
	tuple := PluginCanInvokeTuple(pluginName, tenantID)
	if err := fgaClient.Write(ctx, []Tuple{tuple}); err != nil {
		if errors.Is(err, clients.ErrAlreadyExists) {
			// Tuple already exists — idempotent success.
			return nil
		}
		return fmt.Errorf("fga: WritePluginCanInvokeGrant plugin=%s tenant=%s: %w",
			pluginName, tenantID, err)
	}
	return nil
}

// PluginInstall is a minimal descriptor of an existing plugin install used
// by BackfillPluginCanInvokeGrants.
type PluginInstall struct {
	// PluginName is the manifest.metadata.name of the registered plugin
	// (matches AgentEnrollment.Spec.AgentName for plugin enrollments).
	PluginName string
	// TenantID is the tenant this plugin install belongs to.
	TenantID string
}
