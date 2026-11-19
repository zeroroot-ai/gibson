// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package outsideagent renders an outside A2A agent into the objects of the
// Agent gateway (agentgateway, gibson#1403).
//
// For each outside agent it renders one AgentgatewayBackend and one HTTPRoute
// in the namespace of the gateway.
//
//   - The route matches the headers x-gibson-route-tenant and x-gibson-route-agent
//     and only two exact paths: the A2A endpoint "/" and the Agent Card path of
//     the agent. A call of another path, or of another tenant, matches no route.
//     An exact path wins over the prefix route of the daemon, so the headers
//     choose the outside route and nothing else does.
//   - The route removes each x-gibson-* header and x-capability-grant before the
//     call leaves Gibson. The route of the daemon keeps them. An outside route
//     must not leak them. ext-authz runs at the Gateway level before the route,
//     so it has set its headers when the route removes them.
//   - The backend takes the credential from a Secret in the namespace of the
//     gateway. The package renders no credential value.
//
// The package is pure: it does no I/O. The package does not check the address of
// the host. The registration does, and the network policy of the gateway pods
// must enforce it at the time of the call.
package outsideagent

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/zeroroot-ai/gibson/internal/platform/cabundle"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// Labels that mark an object as rendered from an outside agent.
const (
	LabelManagedBy    = "app.kubernetes.io/managed-by"
	LabelTenant       = "gibson.zeroroot.ai/tenant"
	LabelOutsideAgent = "gibson.zeroroot.ai/outside-agent"
	managedByValue    = "gibson-tenant-operator"

	// AnnotationCredentialSecret names the tenant secret that holds the
	// credential of the agent.
	AnnotationCredentialSecret = "gibson.zeroroot.ai/credential-secret"
)

// Agent is one outside agent, as the daemon records it.
type Agent struct {
	// Tenant is the tenant of the record.
	Tenant string
	// Name is the name of the agent in the tenant. It is a DNS label.
	Name string
	// URL is the HTTPS URL of the A2A endpoint.
	URL string
	// CredentialSecret is the name of the tenant secret of the credential. Empty
	// means the agent needs none, and the backend gets no auth policy.
	CredentialSecret string
	// CABundleSecret is the name of the tenant secret with the PEM CA bundle of
	// the agent. Empty means the gateway uses its public roots. The credential
	// Secret holds the bundle under the key ca.crt.
	CABundleSecret string
}

// Config is the install-side configuration of the render.
type Config struct {
	// Namespace is the namespace of the gateway.
	Namespace string
	// GatewayName is the Gateway that the route attaches to. It is the Gateway
	// with the agent listener.
	GatewayName string
}

// Validate reports a missing field.
func (c Config) Validate() error {
	switch {
	case c.Namespace == "":
		return errors.New("outsideagent: the gateway namespace is required")
	case c.GatewayName == "":
		return errors.New("outsideagent: the gateway name is required")
	}
	return nil
}

// ObjectName returns the name of the backend and of the route of an agent.
func ObjectName(tenant, name string) string { return "oa-" + tenant + "-" + name }

// CredentialSecretName returns the name of the Secret that the backend reads.
func CredentialSecretName(tenant, name string) string {
	return ObjectName(tenant, name) + "-credential"
}

// RemovedHeaders are the headers that the route removes before the call leaves
// Gibson. They are the trusted headers that ext-authz sets, the route claim, the
// headers of the Edge rate limit and the task grant.
func RemovedHeaders() []string {
	return []string{
		modelcall.HeaderTenant, modelcall.HeaderSubject, modelcall.HeaderMission, modelcall.HeaderTask,
		modelcall.HeaderRouteTenant, agentcall.HeaderRouteAgent, agentcall.HeaderRouteBank,
		"x-gibson-identity-tenant", "x-gibson-identity-subject",
		"x-capability-grant",
	}
}

// Render returns the gateway objects of an outside agent: the backend first, then
// the route.
func Render(a Agent, cfg Config) ([]*unstructured.Unstructured, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	host, port, basePath, err := splitURL(a.URL)
	if err != nil {
		return nil, err
	}
	if err := validateNames(a); err != nil {
		return nil, err
	}
	base := ObjectName(a.Tenant, a.Name)
	return []*unstructured.Unstructured{
		backend(a, cfg, base, host, port),
		route(a, cfg, base, basePath),
	}, nil
}

func validateNames(a Agent) error {
	if errs := validation.IsDNS1123Label(a.Tenant); len(errs) > 0 {
		return fmt.Errorf("outsideagent: tenant %q is not a DNS label: %s", a.Tenant, strings.Join(errs, "; "))
	}
	if errs := validation.IsDNS1123Label(a.Name); len(errs) > 0 {
		return fmt.Errorf("outsideagent: name %q is not a DNS label: %s", a.Name, strings.Join(errs, "; "))
	}
	if n := len(CredentialSecretName(a.Tenant, a.Name)); n > 253 {
		return fmt.Errorf("outsideagent: the object name is %d characters, over 253", n)
	}
	return nil
}

// splitURL splits https://host[:port][/path] into its parts. It refuses any
// other form, so a bad record cannot reach a route.
func splitURL(raw string) (host string, port int, path string, err error) {
	u, perr := url.Parse(raw)
	switch {
	case perr != nil:
		return "", 0, "", fmt.Errorf("outsideagent: the URL does not parse: %w", perr)
	case u.Scheme != "https":
		return "", 0, "", fmt.Errorf("outsideagent: URL %q is not an https URL", raw)
	case u.Hostname() == "":
		return "", 0, "", fmt.Errorf("outsideagent: URL %q has no host", raw)
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return "", 0, "", fmt.Errorf("outsideagent: URL %q holds a user name, a query or a fragment", raw)
	}
	port = 443
	if p := u.Port(); p != "" {
		n, aerr := strconv.Atoi(p)
		if aerr != nil || n <= 0 || n > 65535 {
			return "", 0, "", fmt.Errorf("outsideagent: URL %q has an invalid port", raw)
		}
		port = n
	}
	return u.Hostname(), port, strings.TrimSuffix(u.Path, "/"), nil
}

func labels(a Agent) map[string]any {
	return map[string]any{
		LabelManagedBy:    managedByValue,
		LabelTenant:       a.Tenant,
		LabelOutsideAgent: a.Name,
	}
}

// backend renders the AgentgatewayBackend. The backend has the A2A type. It
// speaks TLS to the host with the host as the server name. The gateway verifies
// the certificate of the host against the CA bundle of the agent, or against its
// system roots when the agent has none.
func backend(a Agent, cfg Config, name, host string, port int) *unstructured.Unstructured {
	tls := map[string]any{"sni": host}
	if a.CABundleSecret != "" {
		// policies.tls.caCertificateRefs of the AgentgatewayBackend CRD. A Secret
		// reference reads the PEM bundle from the key ca.crt of the credential
		// Secret.
		tls["caCertificateRefs"] = []any{map[string]any{
			"kind": "Secret", "name": CredentialSecretName(a.Tenant, a.Name), "key": cabundle.Key,
		}}
	}
	policies := map[string]any{"tls": tls}
	meta := map[string]any{"name": name, "namespace": cfg.Namespace, "labels": labels(a)}
	if a.CredentialSecret != "" {
		policies["auth"] = map[string]any{"secretRef": map[string]any{"name": CredentialSecretName(a.Tenant, a.Name)}}
		meta["annotations"] = map[string]any{AnnotationCredentialSecret: a.CredentialSecret}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agentgateway.dev/v1alpha1",
		"kind":       "AgentgatewayBackend",
		"metadata":   meta,
		"spec": map[string]any{
			"a2a":      map[string]any{"host": host, "port": int64(port)},
			"policies": policies,
		},
	}}
}

// route renders the HTTPRoute. Two exact paths match. Each one is rewritten to
// the path of the agent, and the same filter removes the headers.
func route(a Agent, cfg Config, name, basePath string) *unstructured.Unstructured {
	headers := []any{}
	for _, h := range agentcall.RouteHeaders(a.Tenant, a.Name, "") {
		headers = append(headers, map[string]any{"type": "Exact", "name": h.Name, "value": h.Value})
	}
	remove := []any{}
	for _, h := range RemovedHeaders() {
		remove = append(remove, h)
	}
	rule := func(matchPath, targetPath string) map[string]any {
		if targetPath == "" {
			targetPath = "/"
		}
		return map[string]any{
			"matches": []any{map[string]any{
				"path":    map[string]any{"type": "Exact", "value": matchPath},
				"headers": headers,
			}},
			"filters": []any{
				map[string]any{
					"type":                  "RequestHeaderModifier",
					"requestHeaderModifier": map[string]any{"remove": remove},
				},
				map[string]any{
					"type": "URLRewrite",
					"urlRewrite": map[string]any{
						"path": map[string]any{"type": "ReplaceFullPath", "replaceFullPath": targetPath},
					},
				},
			},
			"backendRefs": []any{map[string]any{
				"group": "agentgateway.dev", "kind": "AgentgatewayBackend", "name": name,
			}},
		}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"name": name, "namespace": cfg.Namespace, "labels": labels(a)},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": cfg.GatewayName}},
			"rules": []any{
				rule(agentcall.RouteA2A, basePath),
				rule(agentcall.CardPathFor(a.Name), basePath+agentcall.CardPath),
			},
		},
	}}
}
