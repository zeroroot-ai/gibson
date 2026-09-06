// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package v1alpha1 defines the ConnectorInstance API (ADR-0014).
//
// A ConnectorInstance is gibson's own connector abstraction. The connector-
// operator reconciles it into ToolHive resources (an MCPServer for a hosted
// container connector, or an MCPRemoteProxy for a vendor-hosted one). The
// daemon writes the connector's credential Secret from the tenant's secret
// store (ADR-0015). ToolHive is never exposed to a product surface; the
// wrapper lets gibson replace or upgrade ToolHive without touching the
// catalog, the RPC, or the CLI.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConnectorShape is how the MCP server is hosted. It decides which ToolHive
// primitive the operator creates.
type ConnectorShape string

const (
	// ConnectorShapeHosted runs the MCP server as a container the platform
	// pulls and launches (ToolHive MCPServer). Use it for a vendor with no
	// built-in MCP server (for example a Slack MCP image).
	ConnectorShapeHosted ConnectorShape = "Hosted"
	// ConnectorShapeRemote proxies an MCP server the vendor already runs
	// (ToolHive MCPRemoteProxy). Use it for a vendor with a built-in MCP
	// server (for example GitLab at /api/v4/mcp).
	ConnectorShapeRemote ConnectorShape = "Remote"
)

// ConnectorRuntime is where a Hosted connector runs. The default is a pod in
// the tenant namespace. setec is an opt-in hardening upgrade (ADR-0014).
type ConnectorRuntime string

const (
	// ConnectorRuntimePod runs the connector as a Kubernetes pod with a
	// network egress permission profile. This is the default.
	ConnectorRuntimePod ConnectorRuntime = "pod"
	// ConnectorRuntimeSetec runs the connector as a setec microVM sandbox for
	// hardware isolation. This is a paid upgrade.
	ConnectorRuntimeSetec ConnectorRuntime = "setec"
)

// ConnectorTransport is the MCP transport the server speaks. A stdio server is
// wrapped by ToolHive and re-exposed over http; the operator confirms the
// version against the pinned ToolHive CRD (v1alpha1 as of ToolHive 0.12.1).
type ConnectorTransport string

// Connector transports the operator understands. A stdio server is wrapped by
// ToolHive and re-exposed over HTTP; sse and streamable-http are spoken
// directly.
const (
	ConnectorTransportStdio          ConnectorTransport = "stdio"
	ConnectorTransportSSE            ConnectorTransport = "sse"
	ConnectorTransportStreamableHTTP ConnectorTransport = "streamable-http"
)

// CredentialRef points at ONE entry in the tenant's secret store. The store
// is the hosted OpenBao namespace or the customer's BYO Vault, resolved from
// the tenant's configured secret backend — the same backend the rest of the
// platform reads (ADR-0009). Only the daemon reads that store; the operator
// has no secret-store client (ADR-0015).
type CredentialRef struct {
	// Key is the path/name of the secret in the customer's store.
	// +kubebuilder:validation:Required
	Key string `json:"key"`
	// Property is the field within the secret (for a structured secret).
	// +optional
	Property string `json:"property,omitempty"`
	// TargetEnv is the environment variable the connector reads. Defaults to
	// the vendor's conventional name when unset.
	// +optional
	TargetEnv string `json:"targetEnv,omitempty"`
}

// ConnectorAuthKind is how the connector authenticates to the vendor.
type ConnectorAuthKind string

const (
	// ConnectorAuthNone needs no vendor credential (a public MCP server).
	ConnectorAuthNone ConnectorAuthKind = "none"
	// ConnectorAuthSecret presents a static credential the tenant admin
	// supplied (for example a personal access token). The daemon stores it in
	// the tenant's secret store (ConnectorAuthService.SetConnectorSecret) and
	// writes the connector's credential Secret from it (ADR-0015).
	ConnectorAuthSecret ConnectorAuthKind = "secret"
	// ConnectorAuthOAuth uses the platform OAuth grant. The daemon's
	// ConnectorAuthService mints and rotates a short-lived access token in
	// the tenant's secret store and writes the connector's credential Secret
	// from it (ADR-0015). The human authorizes once (ADR-0014,
	// StartConnectorAuthorization).
	ConnectorAuthOAuth ConnectorAuthKind = "oauth"
)

// ConnectorInstanceSpec is the desired state of one connector for one tenant.
//
// A product caller sets CatalogRef and nothing else — the catalog entry
// supplies the image or endpoint, the transport, the egress allow-list, and the
// auth kind (ADR-0014: "http = catalog + button, not YAML"). The inline fields
// are the advanced escape hatch for a custom connector; the catalog entry fills
// them when CatalogRef is set.
type ConnectorInstanceSpec struct {
	// Connector is the connector name, used for the tool id namespace
	// (mcp:<connector>:<tool>) and the OAuth grant key. For example
	// "connector-gitlab".
	// +kubebuilder:validation:Required
	Connector string `json:"connector"`

	// CatalogRef selects a curated catalog entry. When set, the operator fills
	// the inline fields from the entry; the caller does not author them.
	// +optional
	CatalogRef string `json:"catalogRef,omitempty"`

	// Shape decides the ToolHive primitive: Hosted (container) or Remote
	// (vendor-hosted).
	// +kubebuilder:validation:Enum=Hosted;Remote
	// +kubebuilder:validation:Required
	Shape ConnectorShape `json:"shape"`

	// Image is the container image URL for a Hosted connector. A private
	// registry needs RegistryCredential.
	// +optional
	Image string `json:"image,omitempty"`

	// Endpoint is the vendor MCP URL for a Remote connector (for example
	// https://gitlab.com/api/v4/mcp).
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// Transport is the MCP transport the server speaks.
	// +kubebuilder:validation:Enum=stdio;sse;streamable-http
	// +optional
	Transport ConnectorTransport `json:"transport,omitempty"`

	// Runtime is where a Hosted connector runs. Defaults to pod. setec is a
	// paid hardening upgrade.
	// +kubebuilder:validation:Enum=pod;setec
	// +kubebuilder:default=pod
	// +optional
	Runtime ConnectorRuntime `json:"runtime,omitempty"`

	// EgressAllow is the list of vendor hosts the connector may reach (for
	// example "*.slack.com:443"). The operator renders it into a ToolHive
	// custom permission profile. Enforcement needs a NetworkPolicy-capable CNI
	// (ADR-0014, Spike 1 finding).
	// +optional
	EgressAllow []string `json:"egressAllow,omitempty"`

	// Auth is how the connector authenticates to the vendor.
	// +kubebuilder:validation:Enum=none;secret;oauth
	// +kubebuilder:default=none
	// +optional
	Auth ConnectorAuthKind `json:"auth,omitempty"`

	// Credentials are additional vendor credentials to inject into a Hosted
	// connector as environment variables, each resolved from the tenant's
	// secret store. The bearer credential a connector presents (Auth "secret"
	// or "oauth") is NOT listed here: the daemon stores it under the
	// connector's own name and writes the credential Secret (ADR-0015).
	// Environment injection from this list is not wired yet.
	// +optional
	Credentials []CredentialRef `json:"credentials,omitempty"`

	// RegistryCredential resolves a private-registry pull secret from the
	// customer's store, for a Hosted connector on a private image.
	// +optional
	RegistryCredential *CredentialRef `json:"registryCredential,omitempty"`
}

// ConnectorInstancePhase is the scalar lifecycle phase.
type ConnectorInstancePhase string

const (
	// ConnectorInstancePhasePending is the initial phase before reconcile.
	ConnectorInstancePhasePending ConnectorInstancePhase = "Pending"
	// ConnectorInstancePhaseProvisioning is set while the operator creates the
	// ToolHive resource and the proxy waits for its credential Secret.
	ConnectorInstancePhaseProvisioning ConnectorInstancePhase = "Provisioning"
	// ConnectorInstancePhaseAuthorizationRequired is set for an oauth connector
	// whose grant is not yet authorized. The connector runs but its tools fail
	// until a human authorizes it (ADR-0014).
	ConnectorInstancePhaseAuthorizationRequired ConnectorInstancePhase = "AuthorizationRequired"
	// ConnectorInstancePhaseReady is set once the server runs and its tools are
	// registered in the connector catalog.
	ConnectorInstancePhaseReady ConnectorInstancePhase = "Ready"
	// ConnectorInstancePhaseRefreshFailing is set when the OAuth refresh is
	// failing; the current access token still works but expires without action.
	ConnectorInstancePhaseRefreshFailing ConnectorInstancePhase = "RefreshFailing"
	// ConnectorInstancePhaseFailed is set on a reconcile error (bad image,
	// crashloop, ESO sync failure, egress denial). Status carries the reason.
	ConnectorInstancePhaseFailed ConnectorInstancePhase = "Failed"
	// ConnectorInstancePhaseDeprovisioning is set while the finalizer removes
	// the ToolHive resource and the secret.
	ConnectorInstancePhaseDeprovisioning ConnectorInstancePhase = "Deprovisioning"
)

// ConnectorInstanceStatus is the observed state.
type ConnectorInstanceStatus struct {
	// Phase is the scalar lifecycle phase.
	// +optional
	Phase ConnectorInstancePhase `json:"phase,omitempty"`

	// Conditions carry the detailed reconcile state, one condition per concern
	// (Provisioned, Authorized, ToolsDiscovered, Healthy). Every failure mode
	// is observable here (ADR-0014, the error slice).
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ToolHiveKind and ToolHiveName record the ToolHive resource the operator
	// owns (MCPServer or MCPRemoteProxy). Internal; never a product surface.
	// +optional
	ToolHiveKind string `json:"toolHiveKind,omitempty"`
	// +optional
	ToolHiveName string `json:"toolHiveName,omitempty"`

	// ProxyURL is the in-cluster MCP URL the daemon dials
	// (http://mcp-<name>-proxy.<ns>.svc.cluster.local:8080/mcp).
	// +optional
	ProxyURL string `json:"proxyURL,omitempty"`

	// DiscoveredTools is the count of tools the daemon registered from this
	// connector's tools/list.
	// +optional
	DiscoveredTools int32 `json:"discoveredTools,omitempty"`

	// LastError is the most recent human-readable failure, with remediation.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// ObservedGeneration is the .metadata.generation the status reflects.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ci;connector
// +kubebuilder:printcolumn:name="Connector",type=string,JSONPath=`.spec.connector`
// +kubebuilder:printcolumn:name="Shape",type=string,JSONPath=`.spec.shape`
// +kubebuilder:printcolumn:name="Runtime",type=string,JSONPath=`.spec.runtime`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Tools",type=integer,JSONPath=`.status.discoveredTools`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ConnectorInstance is one connector enabled for one tenant. The connector-
// operator reconciles it into ToolHive resources in the tenant namespace
// (ADR-0014); the daemon writes its credential Secret (ADR-0015).
type ConnectorInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConnectorInstanceSpec   `json:"spec,omitempty"`
	Status ConnectorInstanceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConnectorInstanceList is a list of ConnectorInstance.
type ConnectorInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectorInstance `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConnectorInstance{}, &ConnectorInstanceList{})
}
