// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TenantIdentityPhase is the lifecycle phase of a TenantIdentity. It mirrors the
// scalar progress the Tenant saga records across its identity step
// (EnsureZitadelOrg → … → RemoveZitadelOrg on teardown).
type TenantIdentityPhase string

const (
	// TenantIdentityPhasePending is the initial phase before any identity
	// component has been provisioned.
	TenantIdentityPhasePending TenantIdentityPhase = "Pending"
	// TenantIdentityPhaseProvisioning is set while the provisioning pipeline is
	// actively reconciling the tenant identity.
	TenantIdentityPhaseProvisioning TenantIdentityPhase = "Provisioning"
	// TenantIdentityPhaseReady is set once the Zitadel organization (and any
	// requested OIDC client) exists.
	TenantIdentityPhaseReady TenantIdentityPhase = "Ready"
	// TenantIdentityPhaseFailed is set when the provisioning pipeline returned
	// an error on the most recent reconcile.
	TenantIdentityPhaseFailed TenantIdentityPhase = "Failed"
	// TenantIdentityPhaseDeprovisioning is set while the finalizer teardown is
	// removing the per-tenant identity.
	TenantIdentityPhaseDeprovisioning TenantIdentityPhase = "Deprovisioning"
)

// TenantIdentityOIDCClient declares an OIDC client the tenant identity should
// carry. It mirrors the shape the dashboard's "Register Agent" / login flows
// expect of a Zitadel OIDC application.
//
// NOTE (E8/gibson#803): the Tenant provisioning saga today provisions the
// per-tenant Zitadel *organization* only — there is no OIDC-application saga
// step, and the operator's zitadel.Client exposes organization + service-
// account methods, not OIDC-app methods (per-tenant OIDC clients are minted
// daemon-side by the MembershipService / native-cli-login work, not by this
// operator). This field is therefore a declarative request recorded on the CR
// for the daemon/dashboard surface and reflected in the oidc-client component
// condition; the operator does not itself create the Zitadel OIDC application
// in this slice. See the gibson#803 overlap note.
type TenantIdentityOIDCClient struct {
	// Name is the OIDC client's application name within the tenant org.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// RedirectURIs are the allowed redirect URIs for the OIDC client.
	// +optional
	RedirectURIs []string `json:"redirectURIs,omitempty"`
}

// TenantIdentitySpec defines the desired state of a TenantIdentity.
//
// The CRD is a thin declarative wrapper over the existing identity-provisioning
// code: the controller reconciles the tenant identity by delegating to the same
// zitadel.Client the Tenant saga's EnsureZitadelOrg / RemoveZitadelOrg steps use
// (via the shared identity.Provisioner — one codepath, ADR-0027). The Zitadel
// org name/slug are derived from the tenant the same way the saga derives them
// (display name + tenant id slug); the spec carries the tenant id plus the
// display name used as the org name and an optional OIDC-client request.
type TenantIdentitySpec struct {
	// TenantID is the canonical tenant identifier (the Tenant CR name). The
	// Zitadel org slug is keyed on this value, matching the saga
	// (CreateOrganization(displayName, tenantID)). Immutable once set.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="tenantID is immutable"
	// +required
	TenantID string `json:"tenantID"`

	// DisplayName is the human-readable org name created in Zitadel. The saga's
	// EnsureZitadelOrg passes Tenant.Spec.DisplayName as the org name; when empty
	// the operator falls back to the tenant id (matching the saga's behaviour for
	// tenants without a display name).
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// OIDCClients declares the OIDC clients the tenant identity should carry.
	// Recorded on the CR for the daemon/dashboard surface and reflected in the
	// oidc-client component condition. See TenantIdentityOIDCClient for the
	// gibson#803 scope note on operator-side OIDC provisioning.
	// +optional
	OIDCClients []TenantIdentityOIDCClient `json:"oidcClients,omitempty"`
}

// TenantIdentityComponentCondition reports the provisioning state of a single
// identity component. The aggregate Ready condition (and the scalar Ready field)
// is True only when every participating component has reached state=ready.
type TenantIdentityComponentCondition struct {
	// Name identifies the component: zitadel-org (the per-tenant Zitadel
	// organization) or oidc-client (the per-tenant OIDC application request).
	// +kubebuilder:validation:Enum=zitadel-org;oidc-client
	Name string `json:"name"`

	// State is the current provisioning state of the component.
	// +kubebuilder:validation:Enum=provisioning;ready;failed
	State string `json:"state"`

	// Reason carries a human-readable description, especially when state=failed.
	// +optional
	Reason string `json:"reason,omitempty"`

	// LastUpdated is the time this component's state was last written.
	// +optional
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
}

// TenantIdentityStatus defines the observed state of a TenantIdentity. It
// carries a readiness condition per component plus an overall Ready condition,
// mirroring the scalar progress the Tenant saga records across its identity step.
type TenantIdentityStatus struct {
	// Phase is the overall lifecycle phase of the tenant identity.
	// +kubebuilder:validation:Enum=Pending;Provisioning;Ready;Failed;Deprovisioning
	// +optional
	Phase TenantIdentityPhase `json:"phase,omitempty"`

	// Ready is true when the Zitadel org (and any requested OIDC client) exists.
	// +optional
	Ready bool `json:"ready"`

	// ZitadelOrgID is the Zitadel organization ID provisioned for this tenant.
	// Written the SAME way the saga's EnsureZitadelOrg step writes
	// Tenant.Status.ZitadelOrgID, so the daemon/dashboard read identical data
	// regardless of which codepath provisioned it.
	// +optional
	ZitadelOrgID string `json:"zitadelOrgID,omitempty"`

	// ZitadelOrgSlug is the Zitadel primary domain / slug for this tenant's
	// organization (the tenant id), mirroring Tenant.Status.ZitadelOrgSlug.
	// +optional
	ZitadelOrgSlug string `json:"zitadelOrgSlug,omitempty"`

	// Components carries the per-component provisioning state.
	// +listType=map
	// +listMapKey=name
	// +optional
	Components []TenantIdentityComponentCondition `json:"components,omitempty"`

	// Conditions represent the current state of the TenantIdentity resource.
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
// +kubebuilder:resource:scope=Namespaced,shortName=tid
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.spec.tenantID`
// +kubebuilder:printcolumn:name="OrgID",type=string,JSONPath=`.status.zitadelOrgID`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TenantIdentity is the Schema for the tenantidentities API. It declaratively
// composes the per-tenant identity — the Zitadel organization (and any requested
// OIDC client) — for a single tenant. The controller reconciles the identity by
// delegating to the shared identity.Provisioner (which wraps the same
// zitadel.Client the Tenant saga uses), drift-corrects on every reconcile, and
// tears the identity down on delete via a finalizer.
type TenantIdentity struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec TenantIdentitySpec `json:"spec"`

	// +optional
	Status TenantIdentityStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// TenantIdentityList contains a list of TenantIdentity.
type TenantIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []TenantIdentity `json:"items"`
}

// TenantIdentityFinalizer guarantees the per-tenant identity is deprovisioned
// before the CR is garbage-collected.
const TenantIdentityFinalizer = "gibson.zeroroot.ai/tenantidentity-cleanup"

// TenantIdentity condition types.
const (
	// ConditionTenantIdentityReady is set True once the Zitadel org (and any
	// requested OIDC client) exists.
	//
	// Named *TenantIdentityReady (not ConditionIdentityReady) to avoid collision
	// with any future Tenant.status identity condition the saga may write.
	ConditionTenantIdentityReady = "Ready"
)

func init() {
	SchemeBuilder.Register(&TenantIdentity{}, &TenantIdentityList{})
}
