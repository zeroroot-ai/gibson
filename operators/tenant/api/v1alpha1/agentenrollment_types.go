// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

// The reachable lifecycle, in the order the controller walks it: a new
// enrollment is Pending, the grant-issuance saga takes it to Active, and it
// leaves by explicit revocation, deletion, or saga failure. Phases the
// controller cannot reach are not declared — an enum value that describes a
// step nothing performs is a promise the resource does not keep (gibson#1188).
const (
	AgentEnrollmentPhasePending    AgentEnrollmentPhase = "Pending"
	AgentEnrollmentPhaseActive     AgentEnrollmentPhase = "Active"
	AgentEnrollmentPhaseRevoked    AgentEnrollmentPhase = "Revoked"
	AgentEnrollmentPhaseFailed     AgentEnrollmentPhase = "Failed"
	AgentEnrollmentPhaseTerminated AgentEnrollmentPhase = "Terminated"
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
	// +kubebuilder:validation:Enum=Pending;Active;Revoked;Failed;Terminated
	// +optional
	Phase AgentEnrollmentPhase `json:"phase,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

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
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AgentEnrollment represents an external agent registration.
//
// It carries AUTHORIZATION, not credentials. Reconciling one issues the FGA
// grants that let an already-identified component do its work; it does not mint,
// publish or expire anything the component authenticates with.
//
// A component's bootstrap credential comes from `gibson agent enroll`, run by a
// human against a logged-in CLI session, and is used for exactly one check-in;
// the host key persisted at that moment re-registers the host unattended
// thereafter (ADR-0045). That step is deliberately human-in-the-loop and once.
//
// This resource therefore has no BootstrapReady phase and no bootstrap secret
// reference. It used to declare both, plus a HostID and a LastHeartbeat that no
// controller ever wrote, which read as a second, Kubernetes-native issuance path
// — one where holding RBAC on this namespace would be enough to mint a component
// credential without the device flow. That is a wider authority question than a
// CRD field, and until it is answered deliberately, the resource must not look
// like the answer is yes (gibson#1188).
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
