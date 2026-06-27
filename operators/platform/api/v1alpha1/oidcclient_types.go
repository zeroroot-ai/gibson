// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OIDCClient condition types.
const (
	// ConditionOIDCClientExists indicates the Zitadel-side client has
	// been minted (or detected via status.clientID on re-reconcile).
	ConditionOIDCClientExists = "ClientExists"

	// ConditionOIDCSecretMaterialised indicates the K8s Secret named
	// in spec.secretRef has been populated with clientID + clientSecret.
	ConditionOIDCSecretMaterialised = "SecretMaterialised"
)

// OIDCApplicationType enumerates the OAuth client types we mint. The
// first four values mirror Zitadel's OIDC-app enum; MACHINE_USER is
// our own value that diverts the reconciler away from minting an OIDC
// App and toward minting a Zitadel Machine User (Service User) with
// an IAM_OWNER role and a client-credentials secret. Used by the
// daemon's IDP admin client, which performs an OAuth2 client_credentials
// grant against the issuer's /oauth/v2/token — Zitadel only honors
// that flow for Machine Users (the OIDC-app flow it nominally supports
// for SERVICE clients requires Token Exchange + a separate machine
// identity behind the scenes).
// +kubebuilder:validation:Enum=WEB;NATIVE;USER_AGENT;SERVICE;MACHINE_USER
type OIDCApplicationType string

const (
	// OIDCAppTypeWeb is a confidential server-side web app (dashboard).
	OIDCAppTypeWeb OIDCApplicationType = "WEB"
	// OIDCAppTypeNative is a public client on user devices.
	OIDCAppTypeNative OIDCApplicationType = "NATIVE"
	// OIDCAppTypeUserAgent is a SPA / browser-based public client.
	OIDCAppTypeUserAgent OIDCApplicationType = "USER_AGENT"
	// OIDCAppTypeService is an M2M confidential client. Reserved for
	// future use; the current daemon IDP path uses MACHINE_USER instead.
	OIDCAppTypeService OIDCApplicationType = "SERVICE"
	// OIDCAppTypeMachineUser triggers the Machine-User reconciler path:
	// the resource minted in Zitadel is a Service User (not an OIDC App),
	// it gets IAM_OWNER membership, and the secretRef Secret receives
	// {clientID, clientSecret} from the user's client-credentials grant.
	// The clientID is the user's loginName (NOT the user id), per
	// Zitadel's POST /management/v1/users/{userId}/secret response.
	OIDCAppTypeMachineUser OIDCApplicationType = "MACHINE_USER"
)

// OIDCGrantType enumerates the OAuth grant types Zitadel supports.
// +kubebuilder:validation:Enum=AUTHORIZATION_CODE;IMPLICIT;REFRESH_TOKEN;CLIENT_CREDENTIALS;DEVICE_CODE
type OIDCGrantType string

// OIDCResponseType enumerates the OAuth response types.
// +kubebuilder:validation:Enum=CODE;ID_TOKEN;ID_TOKEN_TOKEN
type OIDCResponseType string

// ProjectReference identifies the Zitadel project a client belongs to.
type ProjectReference struct {
	// Name is the Zitadel project name (not the project ID — the
	// reconciler resolves name → ID via list).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// OIDCClientSpec is the desired state of one Zitadel OIDC client.
type OIDCClientSpec struct {
	// ZitadelIssuer is the OIDC issuer URL. Identical to the parent
	// PlatformBootstrap's spec.zitadel.issuer.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern="^https?://"
	ZitadelIssuer string `json:"zitadelIssuer"`

	// AdminTokenRef points at the IAM_OWNER PAT Secret.
	// +kubebuilder:validation:Required
	AdminTokenRef SecretKeyRef `json:"adminTokenRef"`

	// ProjectRef identifies the Zitadel project to mint the client in.
	// +kubebuilder:validation:Required
	ProjectRef ProjectReference `json:"projectRef"`

	// ClientName is the display name in Zitadel.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ClientName string `json:"clientName"`

	// ApplicationType controls the OAuth client class.
	// +kubebuilder:validation:Required
	ApplicationType OIDCApplicationType `json:"applicationType"`

	// Roles is the set of Zitadel role keys granted to the minted machine
	// user. Only honored for ApplicationType MACHINE_USER. Each entry is
	// classified by its prefix: IAM_-prefixed roles (e.g. IAM_OWNER,
	// IAM_USER_MANAGER, IAM_LOGIN_CLIENT) are granted as instance-scoped
	// IAM members; ORG_-prefixed roles (e.g. ORG_OWNER) are granted as
	// org-scoped members on the project's owning organization. When empty,
	// the reconciler defaults to ["IAM_OWNER"] for backward compatibility
	// with the daemon's IDP admin client. Ignored for OIDC-app types.
	// +optional
	Roles []string `json:"roles,omitempty"`

	// RedirectURIs registers OAuth redirect URIs with Zitadel. Required
	// when ApplicationType is WEB or USER_AGENT; may be empty for SERVICE.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self.all(u, u.startsWith('https://') || u.startsWith('http://localhost'))",message="redirectURIs must use https:// (or http://localhost for dev)"
	RedirectURIs []string `json:"redirectURIs,omitempty"`

	// PostLogoutRedirectURIs registers OAuth post-logout redirect URIs.
	// +optional
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectURIs,omitempty"`

	// GrantTypes registers OAuth grant types with Zitadel.
	// +optional
	GrantTypes []OIDCGrantType `json:"grantTypes,omitempty"`

	// ResponseTypes registers OAuth response types with Zitadel.
	// +optional
	ResponseTypes []OIDCResponseType `json:"responseTypes,omitempty"`

	// AccessTokenLifetimeSeconds overrides the per-application access-token
	// lifetime (Zitadel OIDC app config `accessTokenLifetime`). 0 / unset
	// leaves the instance default. Set to 900 (15m) for the gibson CLI
	// device-grant app so the gibson#622 session-revocation window is bounded:
	// revoking blocks new tokens immediately and the target's current stateless
	// access JWT ages out within this lifetime.
	// +optional
	// +kubebuilder:validation:Minimum=0
	AccessTokenLifetimeSeconds int32 `json:"accessTokenLifetimeSeconds,omitempty"`

	// SecretRef points at the K8s Secret where the reconciler writes
	// clientID + clientSecret. The Secret carries an ownerReference back
	// to this CR for cascade cleanup.
	// +kubebuilder:validation:Required
	SecretRef SecretKeyRef `json:"secretRef"`
}

// OIDCClientStatus is the observed state.
type OIDCClientStatus struct {
	// ObservedGeneration mirrors metadata.generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ClientID is the OAuth client_id Zitadel advertises on its
	// /.well-known/openid-configuration document. The value every
	// downstream OAuth consumer (browser authorize URL, JWT azp
	// claim, client_credentials grant) needs. Persisted BEFORE the
	// corresponding K8s Secret is written, so crash recovery
	// detects existing clients and avoids duplication.
	// +optional
	ClientID string `json:"clientID,omitempty"`

	// AppID is Zitadel's internal application record id, used in
	// management-API URL paths (rotate-secret, delete, get). NOT the
	// same value as ClientID — Zitadel separates the OAuth identity
	// from the management-API identity. Persisted so RotateClientSecret
	// and DeleteOIDCClient hit the correct URL after a reconcile that
	// went through findOIDCClientByName.
	// +optional
	AppID string `json:"appID,omitempty"`

	// Conditions is the standard metav1.Condition slice.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=oidc
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="ClientID",type=string,JSONPath=`.status.clientID`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OIDCClient is one Zitadel OIDC client owned by the platform.
// Typically created as a child of a PlatformBootstrap CR, but can also
// be reconciled standalone for ad-hoc clients.
type OIDCClient struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OIDCClientSpec   `json:"spec,omitempty"`
	Status OIDCClientStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OIDCClientList contains a list of OIDCClient.
type OIDCClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OIDCClient `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OIDCClient{}, &OIDCClientList{})
}
