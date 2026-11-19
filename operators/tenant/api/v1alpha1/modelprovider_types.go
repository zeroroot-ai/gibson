// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ModelProviderType is the kind of model provider that a tenant configured.
type ModelProviderType string

const (
	// ModelProviderAnthropic is the Anthropic API.
	ModelProviderAnthropic ModelProviderType = "anthropic"
	// ModelProviderOpenAI is the OpenAI API.
	ModelProviderOpenAI ModelProviderType = "openai"
	// ModelProviderOpenAICompatible is a service with an OpenAI-shaped API at the
	// base URL of the resource.
	ModelProviderOpenAICompatible ModelProviderType = "openai-compatible"
	// ModelProviderBedrock is Amazon Bedrock. It gets two gateway backends: one
	// for the model calls and one for the model list.
	ModelProviderBedrock ModelProviderType = "bedrock"
	// ModelProviderGemini is the Google Gemini API.
	ModelProviderGemini ModelProviderType = "gemini"
	// ModelProviderVertexAI is Google Vertex AI.
	ModelProviderVertexAI ModelProviderType = "vertexai"
)

// ModelProviderSpec defines one model provider of one tenant. The name of the
// resource is the name of the provider in the tenant. A caller of the model
// gateway selects the provider with that name.
//
// +kubebuilder:validation:XValidation:rule="self.type != 'openai-compatible' || has(self.baseURL)",message="an openai-compatible provider needs a baseURL"
// +kubebuilder:validation:XValidation:rule="self.type != 'bedrock' || has(self.region)",message="a bedrock provider needs a region"
// +kubebuilder:validation:XValidation:rule="self.type != 'vertexai' || (has(self.region) && has(self.projectID))",message="a vertexai provider needs a region and a projectID"
type ModelProviderSpec struct {
	// TenantID is the canonical tenant identifier. The gateway routes of the
	// provider match only the calls of this tenant. Immutable.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="tenantID is immutable"
	// +required
	TenantID string `json:"tenantID"`

	// Type is the kind of the provider. Immutable.
	// +kubebuilder:validation:Enum=anthropic;openai;openai-compatible;bedrock;gemini;vertexai
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="type is immutable"
	// +required
	Type ModelProviderType `json:"type"`

	// BaseURL replaces the default endpoint of the provider. It is required for
	// openai-compatible and optional for anthropic and openai.
	// +kubebuilder:validation:Pattern=`^https://[^/?#@\s]+(/[^?#\s]*)?$`
	// +optional
	BaseURL string `json:"baseURL,omitempty"`

	// Region is the cloud region of a bedrock or vertexai provider.
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+$`
	// +optional
	Region string `json:"region,omitempty"`

	// ProjectID is the Google Cloud project of a vertexai provider.
	// +optional
	ProjectID string `json:"projectID,omitempty"`

	// CredentialSecret is the name of the tenant secret in OpenBao that holds the
	// credential of the provider. The resource holds no credential. The gateway
	// reads the credential from a Kubernetes Secret in its own namespace, and no
	// other workload reads it.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	CredentialSecret string `json:"credentialSecret"`

	// CABundleSecret is the name of the tenant secret that holds the PEM CA
	// bundle that signs the certificate of the backend. Empty means the gateway
	// verifies the backend with its public roots. The resource holds no bundle.
	// The tenant operator copies it into the credential Secret under the key
	// ca.crt.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	CABundleSecret string `json:"caBundleSecret,omitempty"`

	// ModelFilter limits the models that the gateway lets through for this
	// provider. Empty allows every model.
	// +optional
	ModelFilter *ModelFilter `json:"modelFilter,omitempty"`
}

// ModelFilter selects models by name.
type ModelFilter struct {
	// Allow is a list of model name patterns. A pattern may hold the wildcard
	// "*". A model passes when its name matches one pattern.
	// +kubebuilder:validation:MaxItems=64
	// +optional
	Allow []string `json:"allow,omitempty"`
}

// ModelProviderPhase is the lifecycle phase of a ModelProvider.
type ModelProviderPhase string

const (
	// ModelProviderPhasePending is the phase before the first reconcile.
	ModelProviderPhasePending ModelProviderPhase = "Pending"
	// ModelProviderPhaseWaitingForCredential means that the gateway objects are
	// rendered and the credential Secret of the gateway does not exist yet.
	ModelProviderPhaseWaitingForCredential ModelProviderPhase = "WaitingForCredential"
	// ModelProviderPhaseReady means that the gateway objects exist and the
	// credential Secret exists.
	ModelProviderPhaseReady ModelProviderPhase = "Ready"
	// ModelProviderPhaseFailed means that the last reconcile returned an error.
	ModelProviderPhaseFailed ModelProviderPhase = "Failed"
)

// ModelProviderStatus defines the observed state of a ModelProvider.
type ModelProviderStatus struct {
	// Phase is the lifecycle phase.
	// +kubebuilder:validation:Enum=Pending;WaitingForCredential;Ready;Failed
	// +optional
	Phase ModelProviderPhase `json:"phase,omitempty"`

	// Ready is true when the gateway objects exist and the credential Secret
	// exists.
	// +optional
	Ready bool `json:"ready"`

	// CredentialSecretName is the name of the Kubernetes Secret that the gateway
	// reads. Whoever materializes the credential from OpenBao writes that name.
	// +optional
	CredentialSecretName string `json:"credentialSecretName,omitempty"`

	// Conditions represent the current state. Standard condition type: Ready.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastError is the message of the last failed reconcile. It is cleared on a
	// good reconcile.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// ObservedGeneration is the generation that the last reconcile saw.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=mp
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.spec.tenantID`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.status.credentialSecretName`,priority=1
// +kubebuilder:printcolumn:name="LastError",type=string,JSONPath=`.status.lastError`,priority=1

// ModelProvider is one model provider that a tenant configured. The
// tenant-operator renders it into model gateway objects: one backend and one
// route for each provider, and two backends for Bedrock. The routes match only
// the calls of the tenant.
type ModelProvider struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec ModelProviderSpec `json:"spec"`

	// +optional
	Status ModelProviderStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ModelProviderList contains a list of ModelProvider.
type ModelProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ModelProvider `json:"items"`
}

// ModelProviderFinalizer removes the gateway objects of a provider before the
// resource goes away. The gateway objects live in another namespace, so an owner
// reference cannot do it.
const ModelProviderFinalizer = "gibson.zeroroot.ai/modelprovider-cleanup"

// ConditionModelProviderReady is the Ready condition of a ModelProvider.
const ConditionModelProviderReady = "Ready"

func init() {
	SchemeBuilder.Register(&ModelProvider{}, &ModelProviderList{})
}
