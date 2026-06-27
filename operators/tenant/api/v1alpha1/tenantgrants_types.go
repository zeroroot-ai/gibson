// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TenantGrantsPhase is the lifecycle phase of a TenantGrants. It mirrors the
// scalar progress the Tenant saga records across its RegisterTenantWithPlatform
// step (write the tenant→platform registration tuple on provision; delete it on
// teardown).
type TenantGrantsPhase string

const (
	// TenantGrantsPhasePending is the initial phase before any tuple has been
	// reconciled.
	TenantGrantsPhasePending TenantGrantsPhase = "Pending"
	// TenantGrantsPhaseProvisioning is set while the reconciler is actively
	// writing the tenant's FGA tuples.
	TenantGrantsPhaseProvisioning TenantGrantsPhase = "Provisioning"
	// TenantGrantsPhaseReady is set once every declared tuple exists in OpenFGA.
	TenantGrantsPhaseReady TenantGrantsPhase = "Ready"
	// TenantGrantsPhaseFailed is set when the most recent reconcile returned an
	// error writing tuples.
	TenantGrantsPhaseFailed TenantGrantsPhase = "Failed"
	// TenantGrantsPhaseDeprovisioning is set while the finalizer teardown is
	// deleting the tenant's FGA tuples.
	TenantGrantsPhaseDeprovisioning TenantGrantsPhase = "Deprovisioning"
)

// TenantGrantsSpec defines the desired state of a TenantGrants.
//
// The CRD is a thin declarative wrapper over the existing tenant-level FGA
// tuple writes: the controller reconciles the tenant's platform relationships
// by delegating to the shared grants.Provisioner (which wraps the SAME
// fga.Client the Tenant saga's RegisterTenantWithPlatform step uses — one
// codepath, ADR-0027). On every reconcile the controller drift-corrects: any
// declared tuple deleted out-of-band is re-written.
//
// By default (PlatformRegistration true, no ExtraTuples) it reconciles exactly
// the canonical (tenant:<id>, parent, system_tenant:_system) registration tuple
// the saga writes — replacing the imperative RegisterTenantWithPlatform step
// with a declarative, drift-correcting resource.
type TenantGrantsSpec struct {
	// TenantID is the canonical tenant identifier (the Tenant CR name). The
	// platform-registration tuple is keyed on this value, matching the saga
	// (RegisterTenantWithPlatform writes tenant:<TenantID>). Immutable once set.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="tenantID is immutable"
	// +required
	TenantID string `json:"tenantID"`

	// PlatformRegistration requests the canonical tenant→platform registration
	// tuple (tenant:<id>, parent, system_tenant:_system). Defaults to true: the
	// registration tuple is the reason this resource exists, so it participates
	// unless explicitly disabled. Set false only when the registration is owned
	// elsewhere and this resource carries ExtraTuples only.
	// +kubebuilder:default=true
	// +optional
	PlatformRegistration bool `json:"platformRegistration,omitempty"`

	// ExtraTuples declares additional tenant-level FGA tuples to reconcile
	// alongside (or instead of) the platform-registration tuple. Each is written
	// write-if-absent and drift-corrected on every reconcile, and deleted on
	// teardown. Reserved for future tenant-scoped platform relationships; empty
	// in the common case.
	// +listType=atomic
	// +optional
	ExtraTuples []TenantGrantTuple `json:"extraTuples,omitempty"`
}

// TenantGrantTuple is a single declarative FGA relationship tuple. It mirrors
// the operator fga.Tuple {User, Relation, Object} shape; the controller projects
// each entry into a write-if-absent OpenFGA tuple.
type TenantGrantTuple struct {
	// User is the FGA tuple subject, e.g. "tenant:acme".
	// +kubebuilder:validation:MinLength=1
	// +required
	User string `json:"user"`

	// Relation is the FGA relation name, e.g. "parent". Must name a relation
	// that exists in the hand-maintained authz model (internal/platform/authz/
	// model.fga); OpenFGA rejects a write against an unknown or computed
	// relation.
	// +kubebuilder:validation:MinLength=1
	// +required
	Relation string `json:"relation"`

	// Object is the FGA tuple object, e.g. "system_tenant:_system".
	// +kubebuilder:validation:MinLength=1
	// +required
	Object string `json:"object"`
}

// TenantGrantsComponentCondition reports the reconciliation state of a single
// grant component. The aggregate Ready condition (and the scalar Ready field) is
// True only when every participating component has reached state=ready.
type TenantGrantsComponentCondition struct {
	// Name identifies the component: platform-registration (the canonical
	// tenant→platform tuple) or extra-tuples (the ExtraTuples batch).
	// +kubebuilder:validation:Enum=platform-registration;extra-tuples
	Name string `json:"name"`

	// State is the current reconciliation state of the component.
	// +kubebuilder:validation:Enum=provisioning;ready;failed
	State string `json:"state"`

	// Reason carries a human-readable description, especially when state=failed.
	// +optional
	Reason string `json:"reason,omitempty"`

	// LastUpdated is the time this component's state was last written.
	// +optional
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
}

// TenantGrantsStatus defines the observed state of a TenantGrants. It carries a
// readiness condition per component plus an overall Ready condition, mirroring
// the scalar progress the Tenant saga records across its registration step.
type TenantGrantsStatus struct {
	// Phase is the overall lifecycle phase of the tenant grants.
	// +kubebuilder:validation:Enum=Pending;Provisioning;Ready;Failed;Deprovisioning
	// +optional
	Phase TenantGrantsPhase `json:"phase,omitempty"`

	// Ready is true when every declared tuple exists in OpenFGA.
	// +optional
	Ready bool `json:"ready"`

	// AppliedTuples is the number of tuples reconciled on the most recent
	// successful reconcile (platform-registration + ExtraTuples).
	// +optional
	AppliedTuples int `json:"appliedTuples,omitempty"`

	// Components carries the per-component reconciliation state.
	// +listType=map
	// +listMapKey=name
	// +optional
	Components []TenantGrantsComponentCondition `json:"components,omitempty"`

	// Conditions represent the current state of the TenantGrants resource.
	// Standard condition type: Ready.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastError contains the most recent error message from the reconcile.
	// Cleared on a successful reconcile.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// ObservedGeneration reflects the generation most recently reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=tg
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.spec.tenantID`
// +kubebuilder:printcolumn:name="Tuples",type=integer,JSONPath=`.status.appliedTuples`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TenantGrants is the Schema for the tenantgrants API. It declaratively
// reconciles a tenant's platform-level FGA tuples — the relationships that
// register the tenant under the platform's system tenant — for a single tenant.
// The controller reconciles the tuples by delegating to the shared
// grants.Provisioner (which wraps the same fga.Client the Tenant saga's
// RegisterTenantWithPlatform step uses), drift-corrects on every reconcile
// (re-writing any tuple deleted out-of-band), and deletes the tuples on delete
// via a finalizer.
type TenantGrants struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec TenantGrantsSpec `json:"spec"`

	// +optional
	Status TenantGrantsStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// TenantGrantsList contains a list of TenantGrants.
type TenantGrantsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []TenantGrants `json:"items"`
}

// TenantGrantsFinalizer guarantees the tenant's FGA tuples are deleted before
// the CR is garbage-collected.
const TenantGrantsFinalizer = "gibson.zeroroot.ai/tenantgrants-cleanup"

// TenantGrants condition types.
const (
	// ConditionTenantGrantsReady is set True once every declared tuple exists in
	// OpenFGA.
	//
	// Named *TenantGrantsReady (not ConditionGrantsReady) to avoid collision
	// with any future Tenant.status grants condition the saga may write.
	ConditionTenantGrantsReady = "Ready"
)

func init() {
	SchemeBuilder.Register(&TenantGrants{}, &TenantGrantsList{})
}
