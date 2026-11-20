// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// A tenant endpoint for a Remote connector (gibson#1534).
//
// A vendor can host one MCP server for each customer. The URL of that server
// holds the name of the customer, so the catalog cannot state it. The manifest
// states endpointPatterns, and the tenant gives one endpoint at enable time.
// The daemon accepts the endpoint only when it matches a pattern.
//
// The proxy of the connector sends the stored credential of the tenant to the
// endpoint. The check below therefore decides which hosts a credential can
// reach. The rules are strict on purpose:
//
//   - The scheme is https. No user info, no query, no fragment, no escape.
//   - The host is a DNS name. An IP address, a name with one label and a name
//     with a trailing dot are refused. A private or cluster name cannot match
//     a pattern, because a pattern names a vendor domain.
//   - A pattern has an exact host, or a host that starts with one wildcard
//     label ("*.vendor.com"). The wildcard matches exactly one label. The part
//     after it must be a registrable domain. A public suffix such as
//     "herokuapp.com" or "co.uk" is refused, because anyone can make a name
//     below it.
//   - A path segment of a pattern is a literal or one wildcard. The wildcard
//     matches one segment of unreserved characters.
//
// The port is part of the pattern. It is 443 when the pattern states none.

const (
	defaultEndpointPort = "443"
	maxEndpointLen      = 2048
	maxLabelLen         = 63
	maxHostLen          = 253
	maxSegmentLen       = 128
)

// ResolvedEndpoint is the endpoint and the egress allow-list that one
// ConnectorInstance of a tenant gets.
type ResolvedEndpoint struct {
	// Endpoint is the URL of the vendor MCP server. It is empty for a Hosted
	// connector.
	Endpoint string
	// EgressAllow holds host:port entries. For a tenant endpoint it holds only
	// the host of that endpoint.
	EgressAllow []string
}

// endpointParts is a URL in the form that the rules below read.
type endpointParts struct {
	host string // lower case DNS name
	port string // digits, never empty
	path []string
}

// canonical returns the URL in the form that the connector stores.
func (p endpointParts) canonical() string {
	var b strings.Builder
	b.WriteString("https://")
	b.WriteString(p.host)
	if p.port != defaultEndpointPort {
		b.WriteString(":" + p.port)
	}
	if len(p.path) == 0 {
		b.WriteString("/")
	}
	for _, s := range p.path {
		b.WriteString("/" + s)
	}
	return b.String()
}

func (p endpointParts) egress() string { return p.host + ":" + p.port }

// parseEndpointURL splits a URL into endpointParts and refuses each form that
// the rules at the top of this file exclude. A pattern has the same grammar
// as an endpoint, with the wildcards that parsePattern allows, so both use it.
func parseEndpointURL(raw string, wildcards bool) (endpointParts, error) {
	var zero endpointParts
	if raw == "" || len(raw) > maxEndpointLen {
		return zero, fmt.Errorf("the URL must have 1 to %d characters", maxEndpointLen)
	}
	if strings.ContainsAny(raw, "%?#\\ \t\r\n") {
		return zero, errors.New("the URL must hold no escape, query, fragment, backslash or space")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return zero, errors.New("the URL does not parse")
	}
	if u.Scheme != "https" {
		return zero, errors.New("the scheme must be https")
	}
	if u.User != nil || u.Opaque != "" {
		return zero, errors.New("the URL must hold no user info")
	}
	host := u.Hostname()
	if host != strings.ToLower(host) {
		return zero, errors.New("the host must be lower case")
	}
	if err := checkHost(host, wildcards); err != nil {
		return zero, err
	}
	port := u.Port()
	if port == "" {
		port = defaultEndpointPort
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 1 || n > 65535 {
		return zero, errors.New("the port must be a number from 1 to 65535")
	}
	var segs []string
	if p := strings.TrimPrefix(u.Path, "/"); p != "" {
		segs = strings.Split(p, "/")
	}
	for _, s := range segs {
		if err := checkSegment(s, wildcards); err != nil {
			return zero, err
		}
	}
	return endpointParts{host: host, port: port, path: segs}, nil
}

// checkHost refuses a host that is not a DNS name of a vendor. With
// wildcards, the first label may be "*".
func checkHost(host string, wildcards bool) error {
	if host == "" || len(host) > maxHostLen {
		return errors.New("the host is empty or too long")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil || strings.ContainsAny(host, "[]:") {
		return errors.New("the host must be a DNS name, not an IP address")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return errors.New("the host must have at least two labels")
	}
	for i, l := range labels {
		if l == "*" {
			if !wildcards || i != 0 {
				return errors.New("a wildcard is allowed only as the first label of a pattern host")
			}
			continue
		}
		if !validLabel(l) {
			return fmt.Errorf("the host label %q is not a valid DNS label", l)
		}
	}
	return nil
}

func validLabel(l string) bool {
	if l == "" || len(l) > maxLabelLen || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, c := range l {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func unreservedSegment(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > maxSegmentLen {
		return false
	}
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~'
		if !ok {
			return false
		}
	}
	return true
}

func checkSegment(s string, wildcards bool) error {
	if s == "*" && wildcards {
		return nil
	}
	if !unreservedSegment(s) {
		return fmt.Errorf("the path segment %q must hold only letters, digits, and - . _ ~", s)
	}
	return nil
}

// validateEndpointPattern is the loader check of one pattern. It refuses a
// wildcard host that leaves the vendor domain.
func validateEndpointPattern(pattern string) error {
	p, err := parseEndpointURL(pattern, true)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(p.host, "*.") {
		return nil
	}
	suffix := strings.TrimPrefix(p.host, "*.")
	if strings.Contains(suffix, "*") {
		return errors.New("a pattern host holds one wildcard")
	}
	// The suffix must be a registrable domain: one label below a public
	// suffix, or a name below such a domain. A public suffix is open to
	// anyone, so the wildcard would then leave the vendor.
	registrable, err := publicsuffix.EffectiveTLDPlusOne(suffix)
	if err != nil {
		return fmt.Errorf("the wildcard host %q leaves the vendor domain: %q is a public suffix", p.host, suffix)
	}
	if !strings.HasSuffix(suffix, registrable) {
		return fmt.Errorf("the wildcard host %q leaves the vendor domain", p.host)
	}
	return nil
}

// matchPattern reports whether the endpoint parts match the pattern parts.
func matchPattern(pat, ep endpointParts) bool {
	if pat.port != ep.port || len(pat.path) != len(ep.path) {
		return false
	}
	if strings.HasPrefix(pat.host, "*.") {
		suffix := pat.host[1:] // ".vendor.com"
		label, ok := strings.CutSuffix(ep.host, suffix)
		if !ok || label == "" || strings.Contains(label, ".") {
			return false
		}
	} else if pat.host != ep.host {
		return false
	}
	for i, s := range pat.path {
		if s != "*" && s != ep.path[i] {
			return false
		}
	}
	return true
}

// ResolveEndpoint returns the endpoint and the egress allow-list for one
// tenant of this connector.
//
// With no tenant endpoint, the connector gets the endpoint and the egress
// allow-list of the manifest. With a tenant endpoint, the connector gets that
// endpoint, and its egress allow-list holds only the host of that endpoint.
// The daemon calls it at enable time, and again each time it hands the
// connector to the operator, so a manifest that changes a pattern also
// changes what a stored endpoint may be.
func (e ConnectorEntry) ResolveEndpoint(tenantEndpoint string) (ResolvedEndpoint, error) {
	if e.Shape != "Remote" {
		if tenantEndpoint != "" {
			return ResolvedEndpoint{}, fmt.Errorf("connector %q is not a Remote connector and takes no endpoint", e.ID)
		}
		return ResolvedEndpoint{EgressAllow: e.EgressAllow}, nil
	}
	if tenantEndpoint == "" {
		if e.Endpoint == "" {
			return ResolvedEndpoint{}, fmt.Errorf("connector %q needs an endpoint from the tenant", e.ID)
		}
		return ResolvedEndpoint{Endpoint: e.Endpoint, EgressAllow: e.EgressAllow}, nil
	}
	if len(e.EndpointPatterns) == 0 {
		return ResolvedEndpoint{}, fmt.Errorf("connector %q takes no tenant endpoint", e.ID)
	}
	ep, err := parseEndpointURL(tenantEndpoint, false)
	if err != nil {
		return ResolvedEndpoint{}, fmt.Errorf("endpoint of connector %q: %w", e.ID, err)
	}
	for _, raw := range e.EndpointPatterns {
		pat, perr := parseEndpointURL(raw, true)
		if perr != nil {
			continue // the loader refused this pattern, so it cannot be here
		}
		if matchPattern(pat, ep) {
			return ResolvedEndpoint{Endpoint: ep.canonical(), EgressAllow: []string{ep.egress()}}, nil
		}
	}
	return ResolvedEndpoint{}, fmt.Errorf("endpoint of connector %q is outside the vendor patterns: %s",
		e.ID, strings.Join(e.EndpointPatterns, ", "))
}

// validateEndpointPatterns is the loader check of the endpoint fields of a
// Remote connector.
func validateEndpointPatterns(id string, s ConnectorSpec, egress []string) error {
	if len(s.EndpointPatterns) == 0 {
		return nil
	}
	for _, p := range s.EndpointPatterns {
		if err := validateEndpointPattern(p); err != nil {
			return fmt.Errorf("%s: endpointPatterns %q: %w", id, p, err)
		}
	}
	if s.Endpoint == "" {
		// No default endpoint: the egress allow-list comes from the tenant
		// endpoint alone, so the manifest states none.
		if len(egress) > 0 {
			return fmt.Errorf("%s: a connector with endpointPatterns and no endpoint must state no egressAllow: "+
				"the egress follows the endpoint of the tenant", id)
		}
		return nil
	}
	ep, err := parseEndpointURL(s.Endpoint, false)
	if err != nil {
		return fmt.Errorf("%s: endpoint %q: %w", id, s.Endpoint, err)
	}
	for _, raw := range s.EndpointPatterns {
		if pat, perr := parseEndpointURL(raw, true); perr == nil && matchPattern(pat, ep) {
			return nil
		}
	}
	return fmt.Errorf("%s: endpoint %q matches none of endpointPatterns", id, s.Endpoint)
}
