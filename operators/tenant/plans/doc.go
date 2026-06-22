// Package plans is the canonical source of truth for Gibson plan
// definitions consumed by the tenant-operator and (indirectly) the dashboard.
//
// The YAML file plans.yaml in this directory is the authoritative data. It is:
//
//   - Loaded at operator startup via Load() to resolve a tenant's .spec.tier
//     into a runtime quota record (concurrent_missions + concurrent_agents).
//   - Rendered into a Kubernetes ConfigMap by the Helm chart and mounted into
//     the operator pod at /etc/gibson/plans/plans.yaml.
//   - Read directly by the dashboard's prebuild script (scripts/gen-plans.mjs)
//     to generate TypeScript types for the pricing page and billing UI.
//   - Read by codegen scripts that emit the TenantTier const block, the
//     validating-webhook validTiers map, and the dashboard's BillingTier
//     union — see spec plans-and-quotas-simplification.
//
// Plans do not gate the plugin/tool/agent catalog. Every tenant sees every
// catalog item available on the system tenant; access control lives entirely
// in the tenant/team/user/component FGA layers. Plans drive only the two
// runtime quotas: concurrent_missions and concurrent_agents.
//
// A quota value of 0 represents "unlimited"; callers enforcing runtime
// limits must treat 0 as no enforcement.
package plans
