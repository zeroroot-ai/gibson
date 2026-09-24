// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package zitadelconn is the one way an in-cluster component reaches Zitadel
// (ADR-0092).
//
// A component connects to the Zitadel Service by Kubernetes DNS and states the
// public host in the x-zitadel-instance-host header. Zitadel selects its
// instance from that header, so no pod needs to resolve the public name, and
// no request passes through the public edge.
//
// Two facts configure it, and they are the only two names for them:
//
//	ZITADEL_URL              where to connect: the in-cluster Service base URL
//	ZITADEL_EXTERNAL_DOMAIN  what to claim: the public app host, never a port
//
// Endpoints are built from the connect base and Zitadel's fixed paths. An
// absolute URL from a discovery document is never followed, because it names
// the public host, and following it is what once forced every pod to fake
// that name with hostAliases.
//
// The issuer is not derived here. It is a claimed string that a component
// compares and never dials.
package zitadelconn

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// InstanceHostHeader carries the claimed public host on every request.
	// It is chosen over X-Forwarded-Host because proxies rewrite the generic
	// forwarded headers, and this header has one purpose (ADR-0092).
	InstanceHostHeader = "x-zitadel-instance-host"

	// EnvURL names the in-cluster Zitadel Service base URL.
	EnvURL = "ZITADEL_URL"
	// EnvExternalDomain names the claimed public host.
	EnvExternalDomain = "ZITADEL_EXTERNAL_DOMAIN"

	// oauthBase is Zitadel's fixed OAuth2 path prefix.
	oauthBase = "/oauth/v2"
)

// Endpoint is the validated pair of facts. The zero value is not usable; build
// one with New or FromEnv.
type Endpoint struct {
	base *url.URL
	host string
}

// New validates the connect URL and the claimed host.
//
// The connect URL must be an absolute http or https URL with a host and no
// path, query or fragment. The claimed host must be a bare DNS name: no
// scheme, port, path or whitespace. A port is refused because Zitadel stamps
// the issuer from the host it resolves, so a ported host yields a ported
// issuer that every portless check then rejects.
func New(connectURL, externalDomain string) (Endpoint, error) {
	base, err := parseConnectURL(connectURL)
	if err != nil {
		return Endpoint{}, err
	}
	host, err := parseExternalDomain(externalDomain)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{base: base, host: host}, nil
}

// FromEnv builds an Endpoint from ZITADEL_URL and ZITADEL_EXTERNAL_DOMAIN.
func FromEnv() (Endpoint, error) {
	var missing []string
	for _, name := range []string{EnvURL, EnvExternalDomain} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Endpoint{}, fmt.Errorf("zitadelconn: required env vars not set: %v", missing)
	}
	return New(os.Getenv(EnvURL), os.Getenv(EnvExternalDomain))
}

// IsZero reports whether e was never built by New or FromEnv.
func (e Endpoint) IsZero() bool { return e.base == nil }

// Host returns the claimed public host.
func (e Endpoint) Host() string { return e.host }

// BaseURL returns the in-cluster connect base, with no trailing slash.
func (e Endpoint) BaseURL() string {
	if e.base == nil {
		return ""
	}
	return strings.TrimRight(e.base.String(), "/")
}

// URL joins a Zitadel path onto the connect base. path must start with "/".
func (e Endpoint) URL(path string) string {
	return e.BaseURL() + path
}

// TokenURL is Zitadel's OAuth2 token endpoint on the connect base.
func (e Endpoint) TokenURL() string { return e.URL(oauthBase + "/token") }

// JWKSURL is Zitadel's key set endpoint on the connect base.
func (e Endpoint) JWKSURL() string { return e.URL(oauthBase + "/keys") }

// Transport wraps next so every request carries the instance header. A nil
// next means http.DefaultTransport. The caller's request is never mutated.
func (e Endpoint) Transport(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &instanceTransport{host: e.host, next: next}
}

// HTTPClient returns a client whose every request carries the instance
// header. Use it for token, JWKS and Management calls alike.
func (e Endpoint) HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: e.Transport(nil)}
}

type instanceTransport struct {
	host string
	next http.RoundTripper
}

func (t *instanceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set(InstanceHostHeader, t.host)
	resp, err := t.next.RoundTrip(r)
	if err != nil {
		return nil, fmt.Errorf("zitadelconn: %w", err)
	}
	return resp, nil
}

func parseConnectURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("zitadelconn: %s is empty", EnvURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("zitadelconn: %s %q is not a URL: %w", EnvURL, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("zitadelconn: %s %q must use http or https", EnvURL, raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("zitadelconn: %s %q has no host", EnvURL, raw)
	}
	if strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("zitadelconn: %s %q must be a base URL with no path, query or fragment", EnvURL, raw)
	}
	u.Path = ""
	return u, nil
}

var errBadHost = errors.New("must be a bare host name: no scheme, port, path or whitespace")

func parseExternalDomain(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	switch {
	case h == "":
		return "", fmt.Errorf("zitadelconn: %s is empty", EnvExternalDomain)
	case h != raw, strings.ContainsAny(h, " \t\r\n"):
		return "", fmt.Errorf("zitadelconn: %s %q %w", EnvExternalDomain, raw, errBadHost)
	case strings.Contains(h, "://"), strings.ContainsAny(h, "/?#@"):
		return "", fmt.Errorf("zitadelconn: %s %q %w", EnvExternalDomain, raw, errBadHost)
	case strings.Contains(h, ":"):
		return "", fmt.Errorf("zitadelconn: %s %q carries a port; Zitadel would stamp it into the issuer. %w", EnvExternalDomain, raw, errBadHost)
	}
	return strings.ToLower(h), nil
}
