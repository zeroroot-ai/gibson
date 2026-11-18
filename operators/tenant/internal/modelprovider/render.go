// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package modelprovider renders a ModelProvider into the objects of the model
// gateway (agentgateway, gibson#1387, ADR-0172).
//
// For each provider it renders one AgentgatewayBackend and one HTTPRoute. A
// Bedrock provider gets two backends: one for the model calls and one for the
// list call, because the two use two hosts of AWS.
//
// Two facts keep the calls of one tenant away from the routes of another:
//
//   - The route matches the headers x-gibson-tenant and x-gibson-provider and
//     only the three model paths. A call of another path matches no route.
//   - The backend sends the fixed tenant and the fixed provider of the route to
//     ext-authz, in the context extensions of the check. ext-authz refuses a
//     grant whose tenant is not the fixed tenant (internal/server/extauthz).
//     The caller cannot change those two values.
//
// The package renders no credential. The backend names a Kubernetes Secret in
// the namespace of the gateway. The package is pure: it does no I/O.
package modelprovider

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// Names that ext-authz and the callers share. They match
// internal/server/extauthz/modelcall.
const (
	// HeaderTenant and HeaderProvider select the route of a call.
	HeaderTenant   = "x-gibson-tenant"
	HeaderProvider = "x-gibson-provider"

	// ExtTenant and ExtProvider are the context extension keys.
	ExtTenant   = "gibson-tenant"
	ExtProvider = "gibson-provider"

	// MetadataNamespace is the filter metadata namespace of the model name.
	MetadataNamespace = "gibson"

	// RouteResponses, RouteEmbeddings and RouteModels are the three model paths.
	RouteResponses  = "/v1/responses"
	RouteEmbeddings = "/v1/embeddings"
	RouteModels     = "/v1/models"
)

// modelExpression is the CEL expression that reads the exact model name from
// the request body. The gateway sends its result to ext-authz.
const modelExpression = `{"model": json(request.body).model}`

// Labels that mark an object as rendered from a ModelProvider.
const (
	LabelManagedBy     = "app.kubernetes.io/managed-by"
	LabelTenant        = "gibson.zeroroot.ai/tenant"
	LabelModelProvider = "gibson.zeroroot.ai/model-provider"
	LabelSourceNS      = "gibson.zeroroot.ai/model-provider-namespace"
	managedByValue     = "gibson-tenant-operator"
)

// Config is the install-side configuration of the render.
type Config struct {
	// Namespace is the namespace of the gateway. The rendered objects and the
	// credential Secret live there.
	Namespace string
	// GatewayName is the name of the Gateway that the routes attach to.
	GatewayName string
	// ExtAuthzName, ExtAuthzNamespace and ExtAuthzPort name the ext-authz
	// Service that the gateway calls with the gRPC authorization protocol.
	ExtAuthzName      string
	ExtAuthzNamespace string
	ExtAuthzPort      int32
}

// Validate reports a missing field.
func (c Config) Validate() error {
	switch {
	case c.Namespace == "":
		return errors.New("modelprovider: the gateway namespace is required")
	case c.GatewayName == "":
		return errors.New("modelprovider: the gateway name is required")
	case c.ExtAuthzName == "" || c.ExtAuthzPort <= 0:
		return errors.New("modelprovider: the ext-authz service name and port are required")
	}
	return nil
}

// ObjectName returns the base name of the objects of a provider. It is the
// name of the credential Secret too.
func ObjectName(tenant, provider string) string {
	return "mp-" + tenant + "-" + provider
}

// CredentialSecretName returns the name of the Kubernetes Secret that the
// gateway reads for the provider.
func CredentialSecretName(tenant, provider string) string {
	return ObjectName(tenant, provider) + "-credential"
}

// Render returns the gateway objects of a ModelProvider, backends first.
func Render(mp *gibsonv1alpha1.ModelProvider, cfg Config) ([]*unstructured.Unstructured, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := validateNames(mp); err != nil {
		return nil, err
	}
	spec := mp.Spec
	base := ObjectName(spec.TenantID, mp.Name)

	var backends []*unstructured.Unstructured
	var modelBackend, listBackend string
	switch spec.Type {
	case gibsonv1alpha1.ModelProviderBedrock:
		modelBackend, listBackend = base+"-runtime", base+"-control"
		backends = append(backends,
			backend(mp, cfg, modelBackend, bedrockRuntime(spec), awsAuth(spec, mp.Name, ""), true),
			backend(mp, cfg, listBackend, bedrockControl(spec), awsAuth(spec, mp.Name, "bedrock"), false))
	default:
		aiSpec, err := aiProvider(spec)
		if err != nil {
			return nil, err
		}
		modelBackend, listBackend = base, base
		backends = append(backends, backend(mp, cfg, base, aiSpec,
			map[string]any{"secretRef": credentialRef(spec, mp.Name)}, true))
	}
	out := append([]*unstructured.Unstructured(nil), backends...)
	out = append(out, route(mp, cfg, base, modelBackend, listBackend))
	return out, nil
}

// validateNames refuses a name that cannot form an object name.
func validateNames(mp *gibsonv1alpha1.ModelProvider) error {
	if mp.Name == "" {
		return errors.New("modelprovider: the name is required")
	}
	if errs := validation.IsDNS1123Label(mp.Spec.TenantID); len(errs) > 0 {
		return fmt.Errorf("modelprovider: tenant %q is not a DNS label: %s", mp.Spec.TenantID, strings.Join(errs, "; "))
	}
	if errs := validation.IsDNS1123Label(mp.Name); len(errs) > 0 {
		return fmt.Errorf("modelprovider: name %q is not a DNS label: %s", mp.Name, strings.Join(errs, "; "))
	}
	if n := len(CredentialSecretName(mp.Spec.TenantID, mp.Name)) + len("-runtime"); n > 253 {
		return fmt.Errorf("modelprovider: the object name is %d characters, over 253", n)
	}
	return nil
}

// AnnotationCredentialSecret names the tenant secret in OpenBao that holds the
// credential of the provider. Whoever materializes the credential Secret of the
// gateway reads it.
const AnnotationCredentialSecret = "gibson.zeroroot.ai/credential-secret"

func labels(mp *gibsonv1alpha1.ModelProvider) map[string]any {
	return map[string]any{
		LabelManagedBy:     managedByValue,
		LabelTenant:        mp.Spec.TenantID,
		LabelModelProvider: mp.Name,
		LabelSourceNS:      mp.Namespace,
	}
}

// backend wraps a backend spec with the policies that every backend of the
// model gateway has. withAI is false for the list backend of Bedrock, which is a
// plain host, because the AI policies need an AI backend.
func backend(
	mp *gibsonv1alpha1.ModelProvider, cfg Config, name string, spec, auth map[string]any, withAI bool,
) *unstructured.Unstructured {
	policies := map[string]any{
		// The credential comes from a Secret in the namespace of the gateway.
		"auth": auth,
		"extAuth": map[string]any{
			"backendRef": map[string]any{
				"name": cfg.ExtAuthzName, "namespace": nsOrDefault(cfg.ExtAuthzNamespace, cfg.Namespace),
				"port": int64(cfg.ExtAuthzPort),
			},
			"failureMode": "FailClosed",
			"grpc": map[string]any{
				// The fixed values of the route. A caller cannot set them.
				"contextExtensions": map[string]any{
					ExtTenant:   mp.Spec.TenantID,
					ExtProvider: mp.Name,
				},
				// The exact model name, from the request body.
				"requestMetadata": map[string]any{MetadataNamespace: modelExpression},
			},
		},
	}
	if withAI {
		policies["ai"] = map[string]any{
			"routes": map[string]any{
				RouteResponses:  "Responses",
				RouteEmbeddings: "Embeddings",
				RouteModels:     "Passthrough",
			},
		}
		if mp.Spec.ModelFilter != nil && len(mp.Spec.ModelFilter.Allow) > 0 {
			policies["authorization"] = map[string]any{
				"action": "Allow",
				"policy": map[string]any{"matchExpressions": []any{filterExpression(mp.Spec.ModelFilter.Allow)}},
			}
		}
	}
	spec["policies"] = policies

	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agentgateway.dev/v1alpha1",
		"kind":       "AgentgatewayBackend",
		"metadata": map[string]any{
			"name": name, "namespace": cfg.Namespace, "labels": labels(mp),
			"annotations": map[string]any{AnnotationCredentialSecret: mp.Spec.CredentialSecret},
		},
		"spec": spec,
	}}
	return obj
}

func nsOrDefault(ns, def string) string {
	if ns == "" {
		return def
	}
	return ns
}

// filterExpression returns the CEL rule of a model filter. The model list has
// no body and always passes. A call passes when its model matches one pattern.
func filterExpression(patterns []string) string {
	alts := make([]string, 0, len(patterns))
	for _, p := range patterns {
		alts = append(alts, strings.TrimSuffix(strings.TrimPrefix(globToRegexp(p), "^"), "$"))
	}
	return fmt.Sprintf(`request.path == %q || json(request.body).model.matches(%q)`,
		RouteModels, "^(?:"+strings.Join(alts, "|")+")$")
}

// globToRegexp turns a pattern with "*" into an anchored regular expression.
func globToRegexp(glob string) string {
	parts := strings.Split(glob, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return "^" + strings.Join(parts, ".*") + "$"
}

// credentialRef is the reference to the credential Secret of the provider.
func credentialRef(spec gibsonv1alpha1.ModelProviderSpec, provider string) map[string]any {
	return map[string]any{
		"name": CredentialSecretName(spec.TenantID, provider),
	}
}

// aiProvider returns the spec of a backend for a provider that has one AI
// backend.
func aiProvider(spec gibsonv1alpha1.ModelProviderSpec) (map[string]any, error) {
	provider := map[string]any{}
	switch spec.Type {
	case gibsonv1alpha1.ModelProviderAnthropic:
		provider["anthropic"] = map[string]any{}
	case gibsonv1alpha1.ModelProviderOpenAI, gibsonv1alpha1.ModelProviderOpenAICompatible:
		provider["openai"] = map[string]any{}
	case gibsonv1alpha1.ModelProviderGemini:
		provider["gemini"] = map[string]any{}
	case gibsonv1alpha1.ModelProviderVertexAI:
		provider["vertexai"] = map[string]any{"projectId": spec.ProjectID, "region": spec.Region}
	default:
		return nil, fmt.Errorf("modelprovider: type %q has no AI backend", spec.Type)
	}
	if spec.BaseURL != "" {
		host, port, path, err := splitBaseURL(spec.BaseURL)
		if err != nil {
			return nil, err
		}
		provider["host"] = host
		provider["port"] = int64(port)
		if path != "" {
			provider["pathPrefix"] = path
		}
	}
	return map[string]any{"ai": map[string]any{"provider": provider}}, nil
}

// awsAuth signs the call with AWS credentials from the Secret. The model list
// call is signed with the service name "bedrock".
func awsAuth(spec gibsonv1alpha1.ModelProviderSpec, provider, serviceName string) map[string]any {
	aws := map[string]any{"region": spec.Region, "secretRef": credentialRef(spec, provider)}
	if serviceName != "" {
		aws["serviceName"] = serviceName
	}
	return map[string]any{"aws": aws}
}

func bedrockRuntime(spec gibsonv1alpha1.ModelProviderSpec) map[string]any {
	return map[string]any{"ai": map[string]any{"provider": map[string]any{
		"bedrock": map[string]any{"region": spec.Region, "endpointPreference": "RuntimeOnly"},
	}}}
}

// bedrockControl is the backend of the model list call. The list service of AWS
// has the host bedrock.<region>.amazonaws.com. Its signing name is "bedrock".
func bedrockControl(spec gibsonv1alpha1.ModelProviderSpec) map[string]any {
	return map[string]any{"static": map[string]any{
		"host": "bedrock." + spec.Region + ".amazonaws.com", "port": int64(443),
	}}
}

// splitBaseURL splits https://host[:port][/path] into its parts.
func splitBaseURL(raw string) (host string, port int, path string, err error) {
	rest, ok := strings.CutPrefix(raw, "https://")
	if !ok {
		return "", 0, "", fmt.Errorf("modelprovider: baseURL %q is not an https URL", raw)
	}
	hostport, path, _ := strings.Cut(rest, "/")
	if path != "" {
		path = "/" + path
	}
	host, portText, hasPort := strings.Cut(hostport, ":")
	port = 443
	if hasPort {
		if _, scanErr := fmt.Sscanf(portText, "%d", &port); scanErr != nil || port <= 0 || port > 65535 {
			return "", 0, "", fmt.Errorf("modelprovider: baseURL %q has an invalid port", raw)
		}
	}
	if host == "" {
		return "", 0, "", fmt.Errorf("modelprovider: baseURL %q has no host", raw)
	}
	return host, port, strings.TrimSuffix(path, "/"), nil
}

// route renders the HTTPRoute of the provider. The two model paths go to the
// model backend. The list path goes to the list backend.
func route(
	mp *gibsonv1alpha1.ModelProvider, cfg Config, name, modelBackend, listBackend string,
) *unstructured.Unstructured {
	match := func(path string) map[string]any {
		return map[string]any{
			"path": map[string]any{"type": "Exact", "value": path},
			"headers": []any{
				map[string]any{"type": "Exact", "name": HeaderTenant, "value": mp.Spec.TenantID},
				map[string]any{"type": "Exact", "name": HeaderProvider, "value": mp.Name},
			},
		}
	}
	ref := func(backendName string) []any {
		return []any{map[string]any{
			"group": "agentgateway.dev", "kind": "AgentgatewayBackend", "name": backendName,
		}}
	}
	rules := []any{
		map[string]any{
			"matches":     []any{match(RouteResponses), match(RouteEmbeddings)},
			"backendRefs": ref(modelBackend),
		},
		map[string]any{
			"matches":     []any{match(RouteModels)},
			"backendRefs": ref(listBackend),
		},
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata": map[string]any{
			"name": name, "namespace": cfg.Namespace, "labels": labels(mp),
		},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": cfg.GatewayName}},
			"rules":      rules,
		},
	}}
}
