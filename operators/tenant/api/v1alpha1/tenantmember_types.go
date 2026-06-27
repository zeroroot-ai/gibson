// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MemberRole is the role granted to a user within a tenant.
// Valid values are exactly the three FGA relation names on the tenant type
// (spec: tenant-role-taxonomy).
type MemberRole string

const (
	MemberRoleOwner  MemberRole = "owner"
	MemberRoleAdmin  MemberRole = "admin"
	MemberRoleMember MemberRole = "member"
)

// TenantMemberPhase represents the lifecycle phase of a TenantMember.
type TenantMemberPhase string

const (
	TenantMemberPhasePending   TenantMemberPhase = "Pending"
	TenantMemberPhaseInvited   TenantMemberPhase = "Invited"
	TenantMemberPhaseAccepting TenantMemberPhase = "Accepting"
	TenantMemberPhaseActive    TenantMemberPhase = "Active"
	TenantMemberPhaseExpired   TenantMemberPhase = "Expired"
	TenantMemberPhaseRevoked   TenantMemberPhase = "Revoked"
)

// TenantMemberSpec defines the desired state of a TenantMember.
type TenantMemberSpec struct {
	// Email is the email address of the invited user.
	// +kubebuilder:validation:Format=email
	// +required
	Email string `json:"email"`

	// Role is the role granted to the user within the tenant.
	// +kubebuilder:validation:Enum=owner;admin;member
	// +required
	Role MemberRole `json:"role"`

	// TenantRef references the parent Tenant by name.
	// +required
	TenantRef corev1.LocalObjectReference `json:"tenantRef"`

	// AcceptedByUserID is set by the dashboard when the invited user
	// accepts. Triggers Invited -> Active transition.
	// +optional
	AcceptedByUserID string `json:"acceptedByUserId,omitempty"`

	// ResendRequestedAt, when set, requests a fresh invitation email.
	// Controller deduplicates via status.lastResendAt.
	// +optional
	ResendRequestedAt *metav1.Time `json:"resendRequestedAt,omitempty"`

	// InvitedByEmail captures the email of the user who issued the
	// invitation. Empty string means "system-issued" — the controller
	// renders that as "a Gibson admin" in the outgoing email.
	// +kubebuilder:validation:Format=email
	// +optional
	InvitedByEmail string `json:"invitedByEmail,omitempty"`
}

// TenantMemberStatus defines the observed state of a TenantMember.
type TenantMemberStatus struct {
	// +kubebuilder:validation:Enum=Pending;Invited;Accepting;Active;Expired;Revoked
	// +optional
	Phase TenantMemberPhase `json:"phase,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// InvitationTokenHash is the SHA-256 hash of the invitation token.
	// The plaintext token lives only in the Secret referenced below.
	// +optional
	InvitationTokenHash string `json:"invitationTokenHash,omitempty"`

	// InvitationExpiresAt is when the pending invitation expires.
	// +optional
	InvitationExpiresAt *metav1.Time `json:"invitationExpiresAt,omitempty"`

	// InvitationSecretRef is the name of the Secret holding the plaintext
	// invitation token. Deleted when accepted or expired.
	// +optional
	InvitationSecretRef string `json:"invitationSecretRef,omitempty"`

	// UserID is the Zitadel subject (sub claim) recorded after acceptance.
	// +optional
	UserID string `json:"userId,omitempty"`

	// LastResendAt tracks the most recent invitation email sent for
	// resend-request deduplication.
	// +optional
	LastResendAt *metav1.Time `json:"lastResendAt,omitempty"`

	// ZitadelUserID is the Zitadel user ID for this member, set after the
	// EnsureZitadelMember saga step creates or locates the user.
	// +optional
	ZitadelUserID string `json:"zitadelUserID,omitempty"`

	// ZitadelMembershipID is the stable key identifying this user's membership
	// within the tenant's Zitadel organization (composite "orgID/userID").
	// +optional
	ZitadelMembershipID string `json:"zitadelMembershipID,omitempty"`

	// ObservedGeneration reflects the generation most recently reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=tm
// +kubebuilder:printcolumn:name="Email",type=string,JSONPath=`.spec.email`
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=`.spec.role`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TenantMember is a user's membership in a Gibson tenant — covering both
// pending invitations and active memberships.
type TenantMember struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state.
	// +required
	Spec TenantMemberSpec `json:"spec"`

	// status defines the observed state.
	// +optional
	Status TenantMemberStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// TenantMemberList contains a list of TenantMember.
type TenantMemberList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []TenantMember `json:"items"`
}

// TenantMemberFinalizer guarantees cleanup on delete.
const TenantMemberFinalizer = "gibson.zeroroot.ai/tenantmember-cleanup"

func init() {
	SchemeBuilder.Register(&TenantMember{}, &TenantMemberList{})
}

// saga.ConditionedObject accessors.
func (t *TenantMember) GetConditions() *[]metav1.Condition { return &t.Status.Conditions }
func (t *TenantMember) GetPhase() string                   { return string(t.Status.Phase) }
func (t *TenantMember) SetPhase(p string)                  { t.Status.Phase = TenantMemberPhase(p) }
func (t *TenantMember) GetObservedGeneration() int64       { return t.Status.ObservedGeneration }
func (t *TenantMember) SetObservedGeneration(g int64)      { t.Status.ObservedGeneration = g }
