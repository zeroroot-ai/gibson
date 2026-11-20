// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// A tenant variable of a Hosted connector (gibson#1508).
//
// Some vendor servers run in the tenant data plane but must reach a host that
// only the customer knows. The Ansible Automation Platform MCP server needs
// BASE_URL, the address of the AAP of the customer. The catalog cannot state
// it. The manifest declares a variable, the tenant gives its value when it
// enables the connector, and the egress allow-list of the pod follows the
// value.
//
//	variables:
//	  - name: base_url
//	    env: BASE_URL
//	    kind: endpoint
//
// The value reaches the pod as the variable env, and its host joins the
// egress allow-list. The rules are strict, because the tenant chooses a host
// that the pod can call:
//
//   - The value is an https URL under the grammar of endpoint.go: no user
//     info, no query, no fragment, no escape, no IP address.
//   - The host is a public DNS name. Its last label must be a public suffix
//     of the ICANN list. This refuses localhost and the names that a cluster
//     or a private network uses (.svc, .cluster.local, .local, .internal,
//     .lan, .corp, .home.arpa).
//   - The port is 443 or a number from 1024 to 65535. A system port such as
//     22 or 25 is refused.
//   - The manifest can state patterns, with the grammar of endpointPatterns.
//     The value must then match one of them. With no pattern, any public DNS
//     name is allowed, because the host belongs to the customer.
//   - The egress entry is the exact host:port of the value. It is never a
//     wildcard.
//
// A name that is public can still resolve to a private address. The
// CiliumNetworkPolicy of the connector refuses private addresses (ADR-0114),
// and that check is the second layer. The daemon does not resolve the name.

// Values of TenantVariable.Kind.
const (
	// VariableKindEndpoint is an https URL. It is the only kind.
	VariableKindEndpoint = "endpoint"
)

// maxTenantVariables bounds the number of variables of one connector.
const maxTenantVariables = 4

// TenantVariable declares one value that the tenant gives for a Hosted
// connector.
type TenantVariable struct {
	// Name is the key that the tenant uses in the enable request.
	Name string `yaml:"name"`
	// Env is the environment variable of the pod that gets the value.
	Env string `yaml:"env"`
	// Kind is "endpoint".
	Kind string `yaml:"kind"`
	// Patterns limit the value. See endpointPatterns for the grammar. Empty
	// means any public DNS name.
	Patterns []string `yaml:"patterns"`
}

// ResolvedVariables is what the tenant values give to one Hosted connector.
type ResolvedVariables struct {
	// Env holds the canonical value of each variable by its Env name.
	Env map[string]string
	// EgressAllow holds the host:port of each value, sorted, with no repeat.
	EgressAllow []string
}

var variableNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// validateTenantVariables is the loader check of the variables of a connector.
func validateTenantVariables(id string, s ConnectorSpec) error {
	if len(s.Variables) == 0 {
		return nil
	}
	if s.Shape != connectorv1alpha1.ConnectorShapeHosted {
		return fmt.Errorf("%s: variables need a Hosted connector: a Remote connector uses endpointPatterns", id)
	}
	if len(s.Variables) > maxTenantVariables {
		return fmt.Errorf("%s: a connector has at most %d variables", id, maxTenantVariables)
	}
	names := map[string]bool{}
	envs := map[string]bool{}
	for _, c := range s.Credentials {
		envs[c.Env] = true
	}
	for k := range s.Env {
		envs[k] = true
	}
	for _, v := range s.Variables {
		if !variableNameRE.MatchString(v.Name) {
			return fmt.Errorf("%s: variable name %q must be lower case letters, digits and _", id, v.Name)
		}
		if names[v.Name] {
			return fmt.Errorf("%s: variable %q is declared twice", id, v.Name)
		}
		names[v.Name] = true
		if !envNameRE.MatchString(v.Env) {
			return fmt.Errorf("%s: variable %q has env %q, which is not a valid variable name", id, v.Name, v.Env)
		}
		if envs[v.Env] {
			return fmt.Errorf("%s: variable %q sets %q, which credentials or env already set", id, v.Name, v.Env)
		}
		envs[v.Env] = true
		if v.Kind != VariableKindEndpoint {
			return fmt.Errorf("%s: variable %q has kind %q, which must be %q", id, v.Name, v.Kind, VariableKindEndpoint)
		}
		for _, p := range v.Patterns {
			if err := validateEndpointPattern(p); err != nil {
				return fmt.Errorf("%s: variable %q pattern %q: %w", id, v.Name, p, err)
			}
		}
	}
	return nil
}

// checkPublicHost refuses a host that a cluster or a private network can own.
// A public suffix of the ICANN list ends the name of a host on the public
// internet. The other suffixes (.local, .internal, .svc, .corp) do not.
func checkPublicHost(host string) error {
	suffix, icann := publicsuffix.PublicSuffix(host)
	if !icann {
		return fmt.Errorf("the host %q does not end in a public suffix: a name of a cluster or of a private network is refused", host)
	}
	if host == suffix {
		return fmt.Errorf("the host %q is a public suffix", host)
	}
	if suffix == "arpa" || strings.HasSuffix(suffix, ".arpa") {
		return fmt.Errorf("the host %q is in a zone for infrastructure names", host)
	}
	return nil
}

// checkVariablePort allows 443 and the ports from 1024 up.
func checkVariablePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || (n != 443 && n < 1024) || n > 65535 {
		return fmt.Errorf("the port %q must be 443 or a number from 1024 to 65535", port)
	}
	return nil
}

// ResolveVariables checks the values that a tenant gave for the variables of
// the connector. It returns the environment of the pod and the egress hosts. It
// fails when a declared variable has no value, when a value is not declared, or
// when a value breaks a rule above. The daemon calls it at enable time and again
// each time it hands the connector to the operator.
func (e ConnectorEntry) ResolveVariables(values map[string]string) (ResolvedVariables, error) {
	out := ResolvedVariables{Env: map[string]string{}}
	declared := map[string]bool{}
	for _, v := range e.Variables {
		declared[v.Name] = true
	}
	for name := range values {
		if !declared[name] {
			return ResolvedVariables{}, fmt.Errorf("connector %q declares no variable %q", e.ID, name)
		}
	}
	seen := map[string]bool{}
	for _, v := range e.Variables {
		raw, ok := values[v.Name]
		if !ok || raw == "" {
			return ResolvedVariables{}, fmt.Errorf("connector %q needs a value for the variable %q", e.ID, v.Name)
		}
		ep, err := parseEndpointURL(raw, false)
		if err == nil {
			err = checkPublicHost(ep.host)
		}
		if err == nil {
			err = checkVariablePort(ep.port)
		}
		if err == nil && len(v.Patterns) > 0 && !matchesAnyPattern(v.Patterns, ep) {
			err = errors.New("the value is outside the patterns " + strings.Join(v.Patterns, ", "))
		}
		if err != nil {
			return ResolvedVariables{}, fmt.Errorf("variable %q of connector %q: %w", v.Name, e.ID, err)
		}
		out.Env[v.Env] = ep.canonical()
		if h := ep.egress(); !seen[h] {
			seen[h] = true
			out.EgressAllow = append(out.EgressAllow, h)
		}
	}
	sort.Strings(out.EgressAllow)
	return out, nil
}

func matchesAnyPattern(patterns []string, ep endpointParts) bool {
	for _, raw := range patterns {
		if pat, err := parseEndpointURL(raw, true); err == nil && matchPattern(pat, ep) {
			return true
		}
	}
	return false
}
