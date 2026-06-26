// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TenantSecretsBackendPhase is the lifecycle phase of a TenantSecretsBackend.
// It mirrors the scalar progress the Tenant saga records across its three
// secrets-backend steps (ProvisionSecretsBackend → ConfigureSecretsJWTAuth →
// TenantBrokerConfigWritten).
type TenantSecretsBackendPhase string

const (
	// TenantSecretsBackendPhasePending is the initial phase before any
	// component has been provisioned.
	TenantSecretsBackendPhasePending TenantSecretsBackendPhase = "Pending"
	// TenantSecretsBackendPhaseProvisioning is set while the provisioning
	// pipeline is actively reconciling the backend.
	TenantSecretsBackendPhaseProvisioning TenantSecretsBackendPhase = "Provisioning"
	// TenantSecretsBackendPhaseReady is set once the Vault namespace + JWT
	// auth role exist, auth/jwt/config is written, and the broker-config row
	// is published.
	TenantSecretsBackendPhaseReady TenantSecretsBackendPhase = "Ready"
	// TenantSecretsBackendPhaseFailed is set when the provisioning pipeline
	// returned an error on the most recent reconcile.
	TenantSecretsBackendPhaseFailed TenantSecretsBackendPhase = "Failed"
	// TenantSecretsBackendPhaseDeprovisioning is set while the finalizer
	// teardown is removing the per-tenant secrets backend.
	TenantSecretsBackendPhaseDeprovisioning TenantSecretsBackendPhase = "Deprovisioning"
)

// TenantSecretsBackendSpec defines the desired state of a TenantSecretsBackend.
//
// The CRD is a thin declarative wrapper over the existing secrets-backend
// provisioning code: the controller reconciles the backend by delegating to the
// same vault.AdminClient + broker-config writer the Tenant saga's
// ProvisionSecretsBackend / ConfigureSecretsJWTAuth / TenantBrokerConfigWritten
// steps use. The pipeline is keyed entirely on the tenant id; the auth role,
// mount path, namespace template and broker config are operator-side
// configuration (helm values), not per-CR fields — matching the saga, which
// derives them from the operator's Vault configuration rather than from the
// Tenant CR. The spec therefore carries the tenant id plus optional declarative
// overrides for the two values that vary per deployment shape: the KV mount
// path and the JWT-auth role name.
type TenantSecretsBackendSpec struct {
	// TenantID is the canonical tenant identifier (the Tenant CR name). The
	// secrets-backend pipeline keys the Vault namespace, JWT-auth role, and
	// broker-config row on this value. Immutable once set.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="tenantID is immutable"
	// +required
	TenantID string `json:"tenantID"`

	// MountPath optionally overrides the Vault KV v2 mount that holds the
	// tenant's secrets. When empty the operator's Helm-chart default applies
	// (GIBSON_VAULT_MOUNT_PATH, conventionally "secret"). Informational: the
	// underlying vault.AdminClient mounts KV at the operator-configured path;
	// this records the intended value on the CR for observability and a future
	// per-tenant override.
	// +optional
	MountPath string `json:"mountPath,omitempty"`

	// AuthRole optionally overrides the per-tenant JWT-auth role name. When
	// empty the operator derives the conventional "gibson-plugin-<tenantID>"
	// role (ADR-0009), matching the saga. Informational today; recorded on the
	// CR for observability.
	// +optional
	AuthRole string `json:"authRole,omitempty"`
}

// TenantSecretsBackendComponentCondition reports the provisioning state of a
// single backend component. The aggregate Ready condition (and the scalar Ready
// field) is True only when every component has reached state=ready.
type TenantSecretsBackendComponentCondition struct {
	// Name identifies the component: vault-namespace (the per-tenant Vault
	// namespace + JWT-auth role + KV mount), jwt-auth (the auth/jwt/config
	// document), or broker-config (the platform broker-config row).
	// +kubebuilder:validation:Enum=vault-namespace;jwt-auth;broker-config
	Name string `json:"name"`

	// State is the current provisioning state of the component.
	// +kubebuilder:validation:Enum=provisioning;ready;failed
	State string `json:"state"`

	// Reason carries a human-readable description, especially when
	// state=failed.
	// +optional
	Reason string `json:"reason,omitempty"`

	// LastUpdated is the time this component's state was last written.
	// +optional
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
}

// TenantSecretsBackendStatus defines the observed state of a
// TenantSecretsBackend. It carries a readiness condition per component plus an
// overall Ready condition, mirroring the scalar progress the Tenant saga
// records across its secrets-backend steps.
type TenantSecretsBackendStatus struct {
	// Phase is the overall lifecycle phase of the secrets backend.
	// +kubebuilder:validation:Enum=Pending;Provisioning;Ready;Failed;Deprovisioning
	// +optional
	Phase TenantSecretsBackendPhase `json:"phase,omitempty"`

	// Ready is true when the Vault namespace + JWT-auth role exist,
	// auth/jwt/config is written, and the broker-config row is published.
	// +optional
	Ready bool `json:"ready"`

	// Components carries the per-component provisioning state.
	// +listType=map
	// +listMapKey=name
	// +optional
	Components []TenantSecretsBackendComponentCondition `json:"components,omitempty"`

	// Conditions represent the current state of the TenantSecretsBackend
	// resource. Standard condition type: Ready.
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
// +kubebuilder:resource:scope=Namespaced,shortName=tsb
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.spec.tenantID`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TenantSecretsBackend is the Schema for the tenantsecretsbackends API. It
// declaratively composes the per-tenant secrets backend — the OpenBao/Vault
// namespace + JWT-auth role, the auth/jwt/config document, and the platform
// broker-config row — for a single tenant. The controller reconciles the
// backend by delegating to the shared secrets.Provisioner (which wraps the same
// vault.AdminClient + broker-config writer the Tenant saga uses), drift-corrects
// on every reconcile, and tears the backend down on delete via a finalizer.
type TenantSecretsBackend struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec TenantSecretsBackendSpec `json:"spec"`

	// +optional
	Status TenantSecretsBackendStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// TenantSecretsBackendList contains a list of TenantSecretsBackend.
type TenantSecretsBackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []TenantSecretsBackend `json:"items"`
}

// TenantSecretsBackendFinalizer guarantees the per-tenant secrets backend is
// deprovisioned before the CR is garbage-collected.
const TenantSecretsBackendFinalizer = "gibson.zeroroot.ai/tenantsecretsbackend-cleanup"

// TenantSecretsBackend condition types.
const (
	// ConditionSecretsBackendCRReady is set True once the Vault namespace +
	// JWT-auth role exist, auth/jwt/config is written, and the broker-config
	// row is published.
	//
	// Named *CRReady (not ConditionSecretsBackendReady) because that symbol is
	// already taken by the legacy Tenant.status condition the saga still
	// writes (tenant_types.go).
	ConditionSecretsBackendCRReady = "Ready"
)

func init() {
	SchemeBuilder.Register(&TenantSecretsBackend{}, &TenantSecretsBackendList{})
}
