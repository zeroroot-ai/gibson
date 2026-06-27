// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AgentMode is the autonomy mode of an enrolled agent.
type AgentMode string

const (
	AgentModeAutonomous AgentMode = "autonomous"
	AgentModeSupervised AgentMode = "supervised"
)

// ComponentKind is the kind of a platform component referenced by a grant.
type ComponentKind string

const (
	ComponentKindTool   ComponentKind = "tool"
	ComponentKindPlugin ComponentKind = "plugin"
	ComponentKindAgent  ComponentKind = "agent"
)

// ComponentRef references a platform component by kind + name.
type ComponentRef struct {
	// +kubebuilder:validation:Enum=agent;tool;plugin
	Kind ComponentKind `json:"kind"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`
}

// AgentEnrollmentPhase represents the lifecycle phase.
type AgentEnrollmentPhase string

const (
	AgentEnrollmentPhasePending        AgentEnrollmentPhase = "Pending"
	AgentEnrollmentPhaseBootstrapReady AgentEnrollmentPhase = "BootstrapReady"
	AgentEnrollmentPhaseEnrolling      AgentEnrollmentPhase = "Enrolling"
	AgentEnrollmentPhaseActive         AgentEnrollmentPhase = "Active"
	AgentEnrollmentPhaseDegraded       AgentEnrollmentPhase = "Degraded"
	AgentEnrollmentPhaseRevoked        AgentEnrollmentPhase = "Revoked"
	AgentEnrollmentPhaseFailed         AgentEnrollmentPhase = "Failed"
	AgentEnrollmentPhaseTerminated     AgentEnrollmentPhase = "Terminated"
)

// PrincipalKind identifies the FGA principal type for an enrollment. It maps
// to the three distinct identity types provisioned via CreateAgentIdentity in
// the daemon admin API (agent-service-credentials spec).
//
// Absent (empty string) defaults to agent for backward compatibility with
// enrollments created before this field existed.
type PrincipalKind string

const (
	// PrincipalKindAgent represents an agent_principal identity. This is the
	// default when PrincipalKind is unset.
	PrincipalKindAgent PrincipalKind = "agent"
	// PrincipalKindTool represents a tool_principal identity.
	PrincipalKindTool PrincipalKind = "tool"
	// PrincipalKindPlugin represents a plugin_principal identity. Enrollments
	// with this kind receive a (plugin_principal:<id>, can_resolve,
	// secret:tenant-<tenant_id>:*) FGA tuple granting plaintext secret
	// resolution. Agent and tool principals receive no such tuple.
	PrincipalKindPlugin PrincipalKind = "plugin"
)

// AgentEnrollmentSpec defines the desired state.
type AgentEnrollmentSpec struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +required
	AgentName string `json:"agentName"`

	// +kubebuilder:validation:Enum=autonomous;supervised
	// +required
	Mode AgentMode `json:"mode"`

	// PrincipalKind identifies the FGA principal type for this enrollment.
	// Defaults to "agent" when absent. Set to "plugin" to grant the enrollment's
	// principal can_resolve on the tenant's secrets. Set to "tool" for tool
	// identities. Agents and tools receive no secret-resolution grants.
	//
	// +kubebuilder:validation:Enum=agent;tool;plugin
	// +optional
	PrincipalKind PrincipalKind `json:"principalKind,omitempty"`

	// +optional
	ComponentGrants []ComponentRef `json:"componentGrants,omitempty"`

	// +kubebuilder:default:="24h"
	// +optional
	MaxRuntime metav1.Duration `json:"maxRuntime,omitempty"`

	// +optional
	Notes string `json:"notes,omitempty"`
}

// AgentEnrollmentStatus defines the observed state.
type AgentEnrollmentStatus struct {
	// +kubebuilder:validation:Enum=Pending;BootstrapReady;Enrolling;Active;Degraded;Revoked;Failed;Terminated
	// +optional
	Phase AgentEnrollmentPhase `json:"phase,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// HostID is populated after the agent's first /register call.
	// +optional
	HostID string `json:"hostId,omitempty"`

	// +optional
	BootstrapSecretRef string `json:"bootstrapSecretRef,omitempty"`

	// +optional
	BootstrapExpiresAt *metav1.Time `json:"bootstrapExpiresAt,omitempty"`

	// +optional
	LastHeartbeat *metav1.Time `json:"lastHeartbeat,omitempty"`

	// +optional
	GrantsAppliedCount int `json:"grantsAppliedCount,omitempty"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ae
// +kubebuilder:printcolumn:name="Agent",type=string,JSONPath=`.spec.agentName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="HostID",type=string,JSONPath=`.status.hostId`,priority=10
// +kubebuilder:printcolumn:name="LastHeartbeat",type=date,JSONPath=`.status.lastHeartbeat`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AgentEnrollment represents an external agent registration.
type AgentEnrollment struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec AgentEnrollmentSpec `json:"spec"`

	// +optional
	Status AgentEnrollmentStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// AgentEnrollmentList contains a list of AgentEnrollment.
type AgentEnrollmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []AgentEnrollment `json:"items"`
}

// AgentEnrollmentFinalizer ensures cleanup on delete.
const AgentEnrollmentFinalizer = "gibson.zeroroot.ai/enrollment-cleanup"

// RevokeAnnotation triggers explicit revocation without deleting the CR.
const RevokeAnnotation = "gibson.zeroroot.ai/revoke"

func init() {
	SchemeBuilder.Register(&AgentEnrollment{}, &AgentEnrollmentList{})
}

// saga.ConditionedObject accessors.
func (a *AgentEnrollment) GetConditions() *[]metav1.Condition { return &a.Status.Conditions }
func (a *AgentEnrollment) GetPhase() string                   { return string(a.Status.Phase) }
func (a *AgentEnrollment) SetPhase(p string)                  { a.Status.Phase = AgentEnrollmentPhase(p) }
func (a *AgentEnrollment) GetObservedGeneration() int64       { return a.Status.ObservedGeneration }
func (a *AgentEnrollment) SetObservedGeneration(g int64)      { a.Status.ObservedGeneration = g }
