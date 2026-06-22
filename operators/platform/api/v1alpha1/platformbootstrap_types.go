/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Standard condition Types used by PlatformBootstrap.
const (
	// ConditionReady is the top-level rollup. True only when every
	// sub-step condition is True.
	ConditionReady = "Ready"

	// ConditionZitadelProjectReady reports the Zitadel project +
	// service-user provisioning step.
	ConditionZitadelProjectReady = "ZitadelProjectReady"

	// ConditionOIDCClientsReady reports the aggregate of every child
	// OIDCClient CR's Ready condition.
	ConditionOIDCClientsReady = "OIDCClientsReady"

	// ConditionFGAModelLoaded reports the OpenFGA model load step.
	ConditionFGAModelLoaded = "FGAModelLoaded"

	// ConditionVaultTransitReady reports the Vault transit init step.
	// Set True with reason VaultTransitDisabled when spec.vaultTransit.enabled
	// is false (dev clusters).
	ConditionVaultTransitReady = "VaultTransitReady"

	// ConditionPlanSyncComplete reports the plan-sync step.
	ConditionPlanSyncComplete = "PlanSyncComplete"

	// ConditionMasterKeyReady reports the master-key Secret materialisation
	// step. Owned by the platform-operator so helm chart owners don't have
	// to play `lookup` games to keep a randAlphaNum stable across upgrades.
	ConditionMasterKeyReady = "MasterKeyReady"

	// ConditionPostgresBundleReady reports the CNPG database ownership +
	// public-schema grants step. The reconciler connects via the cluster's
	// superuser Secret and runs ALTER DATABASE OWNER + GRANT statements
	// for each declared per-role database. Idempotent.
	ConditionPostgresBundleReady = "PostgresBundleReady"

	// ConditionTrustedDomainReady reports whether the cluster-internal
	// Zitadel Service hostname has been registered as an additional trusted
	// domain on the Zitadel instance. Once true, in-cluster consumers can
	// dial Zitadel by Service name without hostAliases. See ADR-0006.
	ConditionTrustedDomainReady = "TrustedDomainReady"

	// ConditionSAIdentityMapReady reports whether the gibson-sa-identity-map
	// ConfigMap has been populated with the numeric Zitadel subjects of every
	// platform service account. The dashboard's resolve-sa-identity-map init
	// container reads this ConfigMap to build ALLOWED_SERVICE_SUBJECTS for
	// verifyZitadelBearer and hard-fails when any entry is unset. The
	// reconciler collects the iam-admin numeric userId from secret/iam-admin
	// plus each Ready MACHINE_USER OIDCClient child's status.clientID. Replaces
	// the gitops sa-identity-map-populator Sync Job (gitops#170).
	ConditionSAIdentityMapReady = "SAIdentityMapReady"
)

// SecretKeyRef references a key in a Secret. namespace is optional; when
// empty, the controller uses the consuming CR's namespace (or `gibson`
// for cluster-scoped CRs).
type SecretKeyRef struct {
	// Name is the Secret name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace overrides the default namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Key is the entry within the Secret's data map.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// ConfigMapKeyRef references a key in a ConfigMap. Same shape as
// SecretKeyRef.
type ConfigMapKeyRef struct {
	// Name is the ConfigMap name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace overrides the default namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Key is the entry within the ConfigMap's data map.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// ZitadelProjectSpec describes the Zitadel project the platform owns.
type ZitadelProjectSpec struct {
	// Name is the human-readable project name in Zitadel.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// EnsureExists triggers idempotent project creation. When false, the
	// reconciler verifies the project exists but does not create it.
	// +kubebuilder:default=true
	EnsureExists bool `json:"ensureExists,omitempty"`
}

// ZitadelServiceUserSpec describes one machine user the platform mints
// at bootstrap.
type ZitadelServiceUserSpec struct {
	// Name is the Zitadel username for the service account.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Roles is the list of Zitadel role keys assigned to this user
	// (e.g. ["IAM_USER_MANAGER"]).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Roles []string `json:"roles"`

	// PATSecretRef points at the Secret + key where the minted Personal
	// Access Token is materialised.
	// +kubebuilder:validation:Required
	PATSecretRef SecretKeyRef `json:"patSecretRef"`
}

// SystemClientSpec configures the Zitadel System API client used to
// register additional trusted domains on the instance. The System API
// requires a SYSTEM_OWNER machine user authenticated via a signed JWT
// assertion (RFC 7523) — distinct from the IAM_OWNER PAT used by the
// admin-API client.
type SystemClientSpec struct {
	// SystemUserName is the Zitadel SYSTEM_OWNER machine user name.
	// The JWT iss and sub claims are set to this value.
	// Defaults to "gibson-system-bot".
	// +optional
	// +kubebuilder:default="gibson-system-bot"
	SystemUserName string `json:"systemUserName,omitempty"`

	// KeyPath is the file-system path of the RSA private key PEM file
	// provisioned by the chart for the SYSTEM_OWNER user. Falls back to
	// ZITADEL_SYSTEM_KEY_PATH env, then "/etc/zitadel-system/private-key.pem".
	// The chart guarantees this mount; the operator fails at startup when
	// the file is absent.
	// +optional
	KeyPath string `json:"keyPath,omitempty"`

	// TrustedClusterDomain is the cluster-internal Service hostname to
	// register as an additional trusted domain on the Zitadel instance.
	// When empty the controller derives it from the CR name and the
	// operator's namespace: "<cr-name>-zitadel.<namespace>.svc.cluster.local".
	// +optional
	TrustedClusterDomain string `json:"trustedClusterDomain,omitempty"`
}

// ZitadelSpec collects every Zitadel-facing field in one block.
type ZitadelSpec struct {
	// Issuer is the OIDC issuer URL the platform uses for both browser
	// and in-cluster traffic (forge Host header as needed).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern="^https?://"
	Issuer string `json:"issuer"`

	// ExternalDomain is the public hostname (e.g. "app.example.com:30443")
	// forged onto the Host header on every Zitadel API request. Allows the
	// operator to dial Zitadel's in-cluster Service name while satisfying
	// Zitadel's instance router until all consumers are migrated. Equivalent
	// to the ZITADEL_EXTERNAL_DOMAIN env used by the OIDCClient reconciler.
	// +optional
	ExternalDomain string `json:"externalDomain,omitempty"`

	// AdminTokenRef points at the Secret + key holding the IAM_OWNER
	// PAT used to authenticate admin-API calls.
	// +kubebuilder:validation:Required
	AdminTokenRef SecretKeyRef `json:"adminTokenRef"`

	// Project is the per-cluster Zitadel project the platform owns.
	// +kubebuilder:validation:Required
	Project ZitadelProjectSpec `json:"project"`

	// ServiceUsers is the list of machine users the platform mints + the
	// roles each carries.
	// +optional
	ServiceUsers []ZitadelServiceUserSpec `json:"serviceUsers,omitempty"`

	// SystemClient configures the System API client used to register the
	// cluster-internal Zitadel Service hostname as an additional trusted
	// domain. When nil, the TrustedDomainReady step is skipped (for existing
	// clusters without a system-bot user provisioned).
	// +optional
	SystemClient *SystemClientSpec `json:"systemClient,omitempty"`
}

// OIDCClientReference describes one OIDC client the orchestrator will
// reconcile as a child OIDCClient CR.
type OIDCClientReference struct {
	// Name is the K8s name of the OIDCClient CR created by the
	// orchestrator. Also the Zitadel client display name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern="^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
	Name string `json:"name"`

	// ApplicationType controls the OAuth client class minted in Zitadel.
	// Empty defaults to WEB when RedirectURIs is non-empty, else SERVICE.
	// Use MACHINE_USER for daemon/operator IDP admin clients that perform
	// OAuth2 client_credentials grants — Zitadel only honors that grant
	// for Service Users, not OIDC Apps.
	// +optional
	ApplicationType OIDCApplicationType `json:"applicationType,omitempty"`

	// Roles is the set of Zitadel role keys granted to the minted machine
	// user. Only honored for MACHINE_USER entries; threaded onto the child
	// OIDCClient CR's spec.roles. IAM_-prefixed roles become instance IAM
	// members; ORG_-prefixed roles become org members. Empty defaults to
	// ["IAM_OWNER"] in the child reconciler.
	// +optional
	Roles []string `json:"roles,omitempty"`

	// RedirectURIs are the OAuth redirect URIs registered with Zitadel.
	// Required for applicationType WEB; may be empty for service / machine
	// clients.
	// +optional
	RedirectURIs []string `json:"redirectURIs,omitempty"`

	// PostLogoutRedirectURIs are the OAuth post-logout redirect URIs.
	// +optional
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectURIs,omitempty"`

	// GrantTypes overrides the OAuth grant types minted in Zitadel. When
	// empty the orchestrator derives a default from RedirectURIs
	// (AUTHORIZATION_CODE+REFRESH_TOKEN when present, else CLIENT_CREDENTIALS).
	// Set explicitly for the gibson CLI device-grant app, e.g.
	// ["DEVICE_CODE","AUTHORIZATION_CODE","REFRESH_TOKEN"].
	// +optional
	GrantTypes []OIDCGrantType `json:"grantTypes,omitempty"`

	// AccessTokenLifetimeSeconds threads onto the child OIDCClient's
	// per-application access-token lifetime. 0/unset leaves the Zitadel
	// instance default. Set to 900 (15m) for the CLI device-grant app to
	// bound the gibson#622 session-revocation window.
	// +optional
	// +kubebuilder:validation:Minimum=0
	AccessTokenLifetimeSeconds int32 `json:"accessTokenLifetimeSeconds,omitempty"`

	// SecretRef points at the Secret where the minted client secret is
	// materialised. The reconciler writes both clientID + clientSecret
	// into this Secret.
	// +kubebuilder:validation:Required
	SecretRef SecretKeyRef `json:"secretRef"`
}

// FGAModelSpec describes the OpenFGA model load step.
type FGAModelSpec struct {
	// APIEndpoint is the OpenFGA HTTP base URL.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern="^https?://"
	APIEndpoint string `json:"apiEndpoint"`

	// StoreNameRef points at the Secret + key where the OpenFGA store ID
	// is persisted after creation (so subsequent reconciles detect the
	// existing store).
	// +kubebuilder:validation:Required
	StoreNameRef SecretKeyRef `json:"storeNameRef"`

	// ModelConfigMapRef points at the ConfigMap + key holding the FGA
	// model definition (DSL or JSON).
	// +kubebuilder:validation:Required
	ModelConfigMapRef ConfigMapKeyRef `json:"modelConfigMapRef"`
}

// VaultTransitSpec describes the Vault transit-engine init step.
//
// Vault transit + master-kek is structural infrastructure
// ([[feedback-no-service-is-optional]] / ADR-0003 one-code-path). The
// previous `Enabled` toggle has been deleted; the operator unconditionally
// mounts the transit engine and creates the per-cluster master-kek key.
// Operators that genuinely don't run Vault (none exist in our supported
// matrix today) would need a different reconciler, not a toggle.
type VaultTransitSpec struct {
	// Address is the Vault HTTP base URL.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern="^https?://"
	Address string `json:"address"`

	// TokenRef points at the Secret + key holding the Vault admin token.
	// +kubebuilder:validation:Required
	TokenRef SecretKeyRef `json:"tokenRef"`

	// KeyName is the name of the transit key the platform owns.
	// Defaults to "master-kek".
	// +optional
	// +kubebuilder:default="master-kek"
	KeyName string `json:"keyName,omitempty"`
}

// PlanSyncSpec describes the plan-sync step.
type PlanSyncSpec struct {
	// PlansConfigMapRef points at the ConfigMap + key holding the gibson
	// plans data. The reconciler hashes the content and re-syncs only
	// when the hash changes.
	// +kubebuilder:validation:Required
	PlansConfigMapRef ConfigMapKeyRef `json:"plansConfigMapRef"`
}

// MasterKeySpec describes the cluster-wide master-key Secret the platform
// owns. The reconciler creates the Secret with a 32-byte random key the
// first time it runs, and never overwrites an existing value (so chart
// upgrades and operator restarts are non-destructive).
type MasterKeySpec struct {
	// SecretName is the K8s Secret name the operator manages.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`

	// Namespace is the namespace the Secret lives in. Defaults to "gibson".
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Key is the entry within the Secret's data map. Defaults to "master-key".
	// +optional
	Key string `json:"key,omitempty"`
}

// PostgresClusterRef points at a CNPG Cluster the platform owns.
type PostgresClusterRef struct {
	// Host is the in-cluster RW Service hostname (e.g.
	// "platform-postgres-rw.cnpg-system.svc.cluster.local").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`

	// Port is the service port. Defaults to 5432.
	// +optional
	Port int32 `json:"port,omitempty"`

	// SuperuserSecretRef points at the postgres superuser Secret with
	// CNPG-layout keys (`username` + `password`).
	// +kubebuilder:validation:Required
	SuperuserSecretRef SecretKeyRef `json:"superuserSecretRef"`
}

// DatabaseRoleOwnership declares that DB Name should be owned by Owner,
// optionally with public-schema USAGE+CREATE grants to Grants entries.
type DatabaseRoleOwnership struct {
	// Name is the database to ALTER.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Owner is the role to ALTER DATABASE ... OWNER TO.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Owner string `json:"owner"`

	// Grants is an optional list of roles that should receive
	// USAGE+CREATE on the database's public schema.
	// +optional
	Grants []string `json:"grants,omitempty"`
}

// PostgresBundleSpec describes the CNPG database ownership + public-schema
// grants the platform reconciles. Replaces the CNPG `postInitApplicationSQL`
// path, which has subtle semantics around ownership and isn't actually
// applied to every per-role DB.
type PostgresBundleSpec struct {
	// Cluster identifies the CNPG cluster + superuser credentials.
	// +kubebuilder:validation:Required
	Cluster PostgresClusterRef `json:"cluster"`

	// Databases is the list of per-database ownership entries the
	// reconciler enforces.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Databases []DatabaseRoleOwnership `json:"databases"`
}

// PlatformBootstrapSpec is the desired state of the platform.
type PlatformBootstrapSpec struct {
	// Zitadel collects IdP-facing configuration.
	// +kubebuilder:validation:Required
	Zitadel ZitadelSpec `json:"zitadel"`

	// OIDCClients is the list of clients the orchestrator reconciles as
	// child OIDCClient CRs.
	// +optional
	OIDCClients []OIDCClientReference `json:"oidcClients,omitempty"`

	// FGAModel describes the OpenFGA model load. Required — OpenFGA is
	// structural infrastructure (ADR-0003 one-code-path); no skip toggle.
	// +kubebuilder:validation:Required
	FGAModel FGAModelSpec `json:"fgaModel"`

	// VaultTransit describes the Vault transit init. Required — Vault
	// transit + master-kek is structural infrastructure and no `.enabled`
	// toggle exists.
	// +kubebuilder:validation:Required
	VaultTransit VaultTransitSpec `json:"vaultTransit"`

	// PlanSync describes the plan-sync step.
	// +optional
	PlanSync *PlanSyncSpec `json:"planSync,omitempty"`

	// MasterKey describes the cluster-wide master-key Secret the operator
	// owns. Required — the master-kek wrap is structural; no skip toggle.
	// +kubebuilder:validation:Required
	MasterKey MasterKeySpec `json:"masterKey"`

	// PostgresBundle describes the CNPG database ownership + public-schema
	// grants the operator enforces. Required — postgres is structural
	// infrastructure; no skip toggle.
	// +kubebuilder:validation:Required
	PostgresBundle PostgresBundleSpec `json:"postgresBundle"`
}

// OIDCClientStatusEntry mirrors a child OIDCClient's status onto the
// parent for quick `kubectl describe` aggregation.
type OIDCClientStatusEntry struct {
	// Name matches OIDCClientReference.Name.
	Name string `json:"name"`

	// ClientID is the Zitadel client ID once minted.
	// +optional
	ClientID string `json:"clientID,omitempty"`

	// Ready mirrors the child's Ready condition.
	Ready bool `json:"ready"`
}

// PlatformBootstrapStatus is the observed state.
type PlatformBootstrapStatus struct {
	// ObservedGeneration mirrors metadata.generation; used to detect
	// "spec changed, not yet reconciled".
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions is the standard metav1.Condition slice. Top-level Ready
	// rolls up every sub-step condition.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// OIDCClients summarises each child OIDCClient's Ready state.
	// +optional
	OIDCClients []OIDCClientStatusEntry `json:"oidcClients,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PlatformBootstrap is the cluster-scoped orchestrator for the gibson
// platform's bootstrap handshakes. One per cluster.
type PlatformBootstrap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PlatformBootstrapSpec   `json:"spec,omitempty"`
	Status PlatformBootstrapStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PlatformBootstrapList contains a list of PlatformBootstrap.
type PlatformBootstrapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PlatformBootstrap `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PlatformBootstrap{}, &PlatformBootstrapList{})
}
