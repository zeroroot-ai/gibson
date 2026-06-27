// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TenantDataPlaneStorePhase is the lifecycle phase of a single per-tenant
// data store within a TenantDataPlane. It mirrors the scalar progress the
// dataplane.Provisioner pipeline records on the Tenant status today
// (Postgres → Neo4j → Redis → Vector → KEK).
type TenantDataPlaneStorePhase string

const (
	// TenantDataPlanePhasePending is the initial phase before any store has
	// been provisioned.
	TenantDataPlanePhasePending TenantDataPlaneStorePhase = "Pending"
	// TenantDataPlanePhaseProvisioning is set while the provisioning pipeline
	// is actively reconciling the stores.
	TenantDataPlanePhaseProvisioning TenantDataPlaneStorePhase = "Provisioning"
	// TenantDataPlanePhaseReady is set once every requested store is
	// provisioned and the KEK has been initialised.
	TenantDataPlanePhaseReady TenantDataPlaneStorePhase = "Ready"
	// TenantDataPlanePhaseFailed is set when the provisioning pipeline returned
	// an error on the most recent reconcile.
	TenantDataPlanePhaseFailed TenantDataPlaneStorePhase = "Failed"
	// TenantDataPlanePhaseDeprovisioning is set while the finalizer teardown is
	// removing the per-tenant stores.
	TenantDataPlanePhaseDeprovisioning TenantDataPlaneStorePhase = "Deprovisioning"
)

// TenantDataPlaneStores selects which per-tenant stores the data-plane
// pipeline must provision. Every field defaults to true because the existing
// saga unconditionally provisions all stores in the fixed order
// Postgres → Neo4j → Redis → Vector → KEK; the booleans exist so a future
// deployment shape (e.g. graph-less tenant) can opt a store out without a new
// codepath. Setting a store to false is a no-op in the pipeline today — the
// sub-provisioner is simply not invoked.
type TenantDataPlaneStores struct {
	// Postgres requests the per-tenant CNPG Postgres database, role, and
	// schema migrations.
	// +kubebuilder:default=true
	// +optional
	Postgres bool `json:"postgres"`

	// Neo4j requests the per-tenant Neo4j StatefulSet and schema migrations.
	// +kubebuilder:default=true
	// +optional
	Neo4j bool `json:"neo4j"`

	// Redis requests a per-tenant logical DB index in the master Redis index.
	// +kubebuilder:default=true
	// +optional
	Redis bool `json:"redis"`

	// Vector requests the per-tenant RediSearch (vector) index. It rides on the
	// Redis allocation above.
	// +kubebuilder:default=true
	// +optional
	Vector bool `json:"vector"`
}

// TenantDataPlaneSpec defines the desired state of a TenantDataPlane.
//
// The CRD is a thin declarative wrapper over the existing
// dataplane.Provisioner pipeline: the controller reconciles the requested
// stores by delegating to the same pipeline the Tenant saga's
// DataPlaneProvisioned step uses. The pipeline is keyed entirely on the
// tenant id, so the spec carries that id plus the per-store toggles and the
// optional sizing overrides the saga already honours.
type TenantDataPlaneSpec struct {
	// TenantID is the canonical tenant identifier (the Tenant CR name). The
	// data-plane pipeline keys every store on this value. Immutable once set.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="tenantID is immutable"
	// +required
	TenantID string `json:"tenantID"`

	// Stores selects which per-tenant stores to provision. When absent, all
	// stores default to true — matching the current saga, which always
	// provisions the full set.
	// +optional
	Stores TenantDataPlaneStores `json:"stores,omitempty"`

	// Resources optionally overrides per-tenant data-plane resource limits
	// (Postgres connection limit, Redis max-memory). When absent, the
	// operator's Helm-chart defaults apply — identical to the Tenant CR's
	// spec.resources semantics.
	// +optional
	Resources *TenantDataPlaneResources `json:"resources,omitempty"`
}

// TenantDataPlaneStoreCondition reports the provisioning state of a single
// store. The aggregate Ready condition (and the scalar Ready field) is True
// only when every requested store has reached state=ready.
type TenantDataPlaneStoreCondition struct {
	// Name identifies the store: postgres, neo4j, redis, vector, or kek.
	// +kubebuilder:validation:Enum=postgres;neo4j;redis;vector;kek
	Name string `json:"name"`

	// State is the current provisioning state of the store.
	// +kubebuilder:validation:Enum=provisioning;ready;failed
	State string `json:"state"`

	// Reason carries a human-readable description, especially when
	// state=failed.
	// +optional
	Reason string `json:"reason,omitempty"`

	// LastUpdated is the time this store's state was last written.
	// +optional
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
}

// DataPlaneStatus defines the observed state of a TenantDataPlane. It carries
// a readiness condition per store plus an overall Ready condition, mirroring
// the scalar progress the pipeline records on the Tenant status. Named
// DataPlaneStatus (not the conventional TenantDataPlaneStatus) because that
// symbol is already taken by the legacy struct embedded in Tenant.status
// (Tenant.status.dataPlane) which the saga still writes.
type DataPlaneStatus struct {
	// Phase is the overall lifecycle phase of the data plane.
	// +kubebuilder:validation:Enum=Pending;Provisioning;Ready;Failed;Deprovisioning
	// +optional
	Phase TenantDataPlaneStorePhase `json:"phase,omitempty"`

	// Ready is true when every requested store is provisioned and the tenant
	// KEK has been initialised. The daemon's provisioning check reads this
	// (it previously read Tenant.status.dataPlane.ready).
	// +optional
	Ready bool `json:"ready"`

	// Stores carries the per-store provisioning state.
	// +listType=map
	// +listMapKey=name
	// +optional
	Stores []TenantDataPlaneStoreCondition `json:"stores,omitempty"`

	// Conditions represent the current state of the TenantDataPlane resource.
	// Standard condition type: Ready.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastError contains the most recent error message from the provisioning
	// pipeline. Cleared on a successful reconcile.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// ObservedGeneration reflects the generation most recently reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=tdp
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.spec.tenantID`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TenantDataPlane is the Schema for the tenantdataplanes API. It declaratively
// composes the per-tenant CNPG Postgres, Neo4j, and Redis (plus the vector
// index and KEK init) stores for a single tenant. The controller reconciles
// the stores by delegating to the shared dataplane.Provisioner pipeline,
// drift-corrects on every reconcile, and tears the stores down on delete via
// a finalizer.
type TenantDataPlane struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec TenantDataPlaneSpec `json:"spec"`

	// +optional
	Status DataPlaneStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// TenantDataPlaneList contains a list of TenantDataPlane.
type TenantDataPlaneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []TenantDataPlane `json:"items"`
}

// TenantDataPlaneFinalizer guarantees the per-tenant stores are deprovisioned
// before the CR is garbage-collected.
const TenantDataPlaneFinalizer = "gibson.zeroroot.ai/tenantdataplane-cleanup"

// TenantDataPlane condition types.
const (
	// ConditionDataPlaneReady is set True once every requested store is
	// provisioned and the KEK initialised.
	ConditionDataPlaneReady = "Ready"
)

func init() {
	SchemeBuilder.Register(&TenantDataPlane{}, &TenantDataPlaneList{})
}
