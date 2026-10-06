// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TenantPhase represents the lifecycle phase of a Tenant resource.
type TenantPhase string

const (
	TenantPhasePending      TenantPhase = "Pending"
	TenantPhaseProvisioning TenantPhase = "Provisioning"
	TenantPhaseReady        TenantPhase = "Ready"
	TenantPhaseFailed       TenantPhase = "Failed"
	TenantPhaseTerminating  TenantPhase = "Terminating"
	TenantPhaseTerminated   TenantPhase = "Terminated"
)

// TenantTier represents the canonical plan id of a Tenant. The set of
// constants below mirrors plans.yaml. The drift guard this comment used to
// name does not exist -- there is no tier_drift_test.go anywhere in the tree --
// so nothing fails CI when the two diverge (gibson#557).
type TenantTier string

const (
	TenantPlanTeam             TenantTier = "team"
	TenantPlanOrg              TenantTier = "org"
	TenantPlanEnterprise       TenantTier = "enterprise"
	TenantPlanEnterpriseDeploy TenantTier = "enterprise-deploy"
)

// TenantDataPlaneResources carries per-tenant data-plane resource limits that
// override the operator defaults. The Tenant reconciler copies the block onto
// the TenantDataPlane, and the data-plane provisioner applies it on every
// Provision. All fields are optional; a zero value means "use operator
// default".
//
// Redis has no per-tenant limit. A tenant owns one logical database on a
// shared server, and MAXMEMORY is a server-wide setting, so a per-tenant
// Redis memory cap cannot be applied and is not declared here (gibson#545).
type TenantDataPlaneResources struct {
	// PostgresConnectionLimit overrides the default per-role Postgres connection
	// limit (ALTER ROLE ... CONNECTION LIMIT N). 0 = use operator default.
	// +optional
	// +kubebuilder:validation:Minimum=0
	PostgresConnectionLimit int `json:"postgresConnectionLimit,omitempty"`
}

// TenantSpec defines the desired state of a Tenant.
type TenantSpec struct {
	// DisplayName is the human-readable name for this tenant.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=100
	// +required
	DisplayName string `json:"displayName"`

	// Owner is the email address of the tenant owner. Used as the admin user
	// in Zitadel (via Auth.js) and as billing contact in Stripe.
	// +kubebuilder:validation:Format=email
	// +required
	Owner string `json:"owner"`

	// Tier sets the tenant's plan id. Drives daemon quota enforcement
	// (concurrent_missions, concurrent_agents) and Stripe product binding.
	// The enum is generated from plans.yaml; the migration Job at chart
	// upgrade time rewrites legacy values per spec
	// plans-and-quotas-simplification.
	//
	// +kubebuilder:validation:Enum=team;org;enterprise;enterprise-deploy
	// +required
	Tier TenantTier `json:"tier"`

	// Resources allows overriding per-tenant data-plane resource limits. When
	// absent, operator Helm-chart defaults apply. See TenantDataPlaneResources.
	// +optional
	Resources *TenantDataPlaneResources `json:"resources,omitempty"`
}

// DataPlaneStoreStatus reports the provisioning state of a single per-tenant
// data store. Added by spec per-tenant-data-plane-completion Task 21 (D8).
// All fields are optional for backward compatibility.
type DataPlaneStoreStatus struct {
	// State is the current provisioning state.
	// +kubebuilder:validation:Enum=provisioning;ready;failed
	// +optional
	State string `json:"state,omitempty"`
}

// DataPlaneSummary holds the per-store provisioning status for the four
// data-plane stores. It surfaces granular progress to the onboarding UX
// (Task 34, D8). Added by spec per-tenant-data-plane-completion Task 21.
// All fields are optional; zero-value means "not yet reported".
type DataPlaneSummary struct {
	// Postgres reports the provisioning state of the per-tenant Postgres
	// database and role.
	// +optional
	Postgres DataPlaneStoreStatus `json:"postgres,omitempty"`

	// Redis reports the provisioning state of the per-tenant Redis logical
	// database index.
	// +optional
	Redis DataPlaneStoreStatus `json:"redis,omitempty"`

	// Neo4j reports the provisioning state of the per-tenant Neo4j
	// StatefulSet instance.
	// +optional
	Neo4j DataPlaneStoreStatus `json:"neo4j,omitempty"`
}

// TenantDataPlaneStatus reports the observed provisioning state of the four
// per-tenant data stores and the KEK. The daemon's provisioning check
// (Phase B 2.9) polls status.dataPlane.ready before serving traffic for a
// tenant.
type TenantDataPlaneStatus struct {
	// Ready is true when all data-plane stores are provisioned and the tenant
	// KEK has been initialised. The daemon uses this field to gate data access.
	// +optional
	Ready bool `json:"ready"`

	// Phase describes the current provisioning phase.
	// +kubebuilder:validation:Enum=Pending;Provisioning;Active;Failed;Deprovisioning
	// +optional
	Phase string `json:"phase,omitempty"`

	// PostgresProvisioned is true after the per-tenant Postgres database,
	// migrations, and role have been created successfully.
	// +optional
	PostgresProvisioned bool `json:"postgresProvisioned"`

	// Neo4jProvisioned is true after the per-tenant Neo4j database and schema
	// migrations have been applied.
	// +optional
	Neo4jProvisioned bool `json:"neo4jProvisioned"`

	// RedisProvisioned is true after a logical DB index has been allocated for
	// the tenant in the master Redis index.
	// +optional
	RedisProvisioned bool `json:"redisProvisioned"`

	// VectorProvisioned is true after the per-tenant RediSearch index has been
	// created.
	// +optional
	VectorProvisioned bool `json:"vectorProvisioned"`

	// KEKInitialized is true after the per-tenant KEK derivation has been
	// validated (Postgres role password was set with the derived KEK).
	// +optional
	KEKInitialized bool `json:"kekInitialized"`

	// LastError contains the most recent error message from the provisioning
	// pipeline. Cleared on successful completion.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// Stores provides per-store granular provisioning state for the
	// onboarding UX (spec per-tenant-data-plane-completion D8). Added by
	// Task 21; optional, zero-value is backward compatible with existing
	// CRD consumers that only read the scalar bool fields above.
	// +optional
	Stores DataPlaneSummary `json:"stores,omitempty"`
}

// TenantStatus defines the observed state of a Tenant.
type TenantStatus struct {
	// Phase is the current lifecycle phase.
	// +kubebuilder:validation:Enum=Pending;Provisioning;Ready;Failed;Terminating;Terminated
	// +optional
	Phase TenantPhase `json:"phase,omitempty"`

	// Conditions represent the current state of the Tenant resource.
	// Standard condition types: Ready, NamespaceProvisioned, ZitadelOrgReady,
	// StripeReady, FGAReady, RedisReady, Terminating.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Namespace is the Kubernetes namespace provisioned for this tenant.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// ObservedGeneration reflects the generation most recently reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ZitadelOrgID is the Zitadel organization ID provisioned for this tenant.
	// Populated by the EnsureZitadelOrg saga step.
	// +optional
	ZitadelOrgID string `json:"zitadelOrgID,omitempty"`

	// ZitadelOrgSlug is the Zitadel primary domain / slug for this tenant's
	// organization. Mirrors the Tenant name by convention.
	// +optional
	ZitadelOrgSlug string `json:"zitadelOrgSlug,omitempty"`

	// DataPlane reports the per-store provisioning state managed by the
	// database-per-tenant-data-plane pipeline. The daemon polls
	// status.dataPlane.ready before opening data connections for a tenant.
	// +optional
	DataPlane TenantDataPlaneStatus `json:"dataPlane,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=tn
// +kubebuilder:printcolumn:name="Tier",type=string,JSONPath=`.spec.tier`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Namespace",type=string,JSONPath=`.status.namespace`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="DataPlane",type=string,JSONPath=`.status.dataPlane.phase`,priority=1
// +kubebuilder:printcolumn:name="DataPlaneError",type=string,JSONPath=`.status.dataPlane.lastError`,priority=1

// Tenant is the Schema for the tenants API. Represents a single Gibson
// customer's declarative state across all identity and data subsystems.
type Tenant struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of Tenant.
	// +required
	Spec TenantSpec `json:"spec"`

	// status defines the observed state of Tenant.
	// +optional
	Status TenantStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// TenantList contains a list of Tenant.
type TenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Tenant `json:"items"`
}

// Finalizer name applied to Tenants to guarantee cleanup.
const TenantFinalizer = "gibson.zeroroot.ai/tenant-cleanup"

// Condition types for Tenant.
const (
	ConditionReady                = "Ready"
	ConditionNamespaceProvisioned = "NamespaceProvisioned"
	ConditionRedisReady           = "RedisReady"
	ConditionTerminating          = "Terminating"

	// ConditionZitadelOrgReady is set True after the EnsureZitadelOrg saga
	// step has provisioned (or verified) the Zitadel organization for this
	// tenant. Set False with Reason=Deleted by RemoveZitadelOrg on teardown.
	ConditionZitadelOrgReady = "ZitadelOrgReady"

	// ConditionTenantNamePublished is set True after the operator has
	// published the tenant's display name into the Redis cache the daemon's
	// ListMyMemberships RPC reads. Idempotent on every reconcile. Set False
	// with Reason=Deleted by the teardown step on Tenant CR delete.
	ConditionTenantNamePublished = "TenantNamePublished"

	// ConditionBeliefTrainerReady is set True after the operator has created
	// or updated the belief trainer CronJob of the tenant and its
	// NetworkPolicy (ADR-0106, gibson#616). Both carry an owner reference to
	// the Tenant, so a tenant delete removes them.
	ConditionBeliefTrainerReady = "BeliefTrainerReady"

	// ConditionSecretsBackendReady is set True after the operator has
	// provisioned the per-tenant Vault namespace (Enterprise) or
	// path-prefix + ACL policy (Community) for this tenant per spec
	// secrets-broker Requirement 10.3. Set False with Reason=Deleted by
	// the teardown step on Tenant CR delete.
	ConditionSecretsBackendReady = "SecretsBackendReady"

	// ConditionSecretsJWTAuthConfigured is set True after the operator has
	// written the per-tenant `auth/jwt/config` document inside the
	// tenant's Vault namespace (bound_issuer + jwks_url + jwks_ca_pem,
	// mirroring the root namespace set by the chart's
	// openbao-jwt-auth-init Job). Without this condition, the daemon's
	// per-tenant `auth/jwt/login` returns 400 "could not load
	// configuration" and the dashboard 412s on every API call.
	// tenant-operator#189.
	ConditionSecretsJWTAuthConfigured = "SecretsJWTAuthConfigured"

	// ConditionWelcomeEmailSent is set True after the operator has sent the
	// workspace-ready welcome email to the founding owner (spec.owner) at the
	// Tenant's Ready transition. It IS the idempotence guard: Reconcile
	// re-runs on every watch event, so an unguarded send would mail the owner
	// on every requeue. It is written into status and persisted by the
	// reconciler's Status().Patch — a mid-reconcile spec write would be
	// silently discarded (tenant-operator#354). Left unset when the send
	// failed, so the next reconcile retries. gibson#1447.
	ConditionWelcomeEmailSent = "WelcomeEmailSent"
)

func init() {
	SchemeBuilder.Register(&Tenant{}, &TenantList{})
}
