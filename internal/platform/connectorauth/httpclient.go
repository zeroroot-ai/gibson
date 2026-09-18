// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package connectorauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/netguard"
)

// maxRedirects bounds a discovery or token exchange that keeps bouncing.
const maxRedirects = 5

// NewHTTPClient returns the client every connector OAuth call (discovery,
// dynamic registration, code exchange, refresh) must use. The instance URL
// comes from a tenant admin, and discovery then follows whatever endpoints
// that instance advertises, so every hop is attacker-chosen. Two guards, and
// both run on every request including each redirect:
//
//   - the netguard dialer refuses, at connect time, any address in a blocked
//     class (loopback, private, link-local, the cloud metadata service);
//   - the transport refuses any URL that is not https, so a redirect cannot
//     downgrade to plaintext and the guard cannot be sidestepped by a scheme
//     the dialer never sees.
//
// allowPrivate lifts both for an operator whose connector vendor lives on the
// private network (security.allow_private_connector_endpoints). It is a
// separate knob from the LLM one on purpose: an operator running a local
// model server has not thereby agreed to let a tenant admin aim the daemon
// at the cluster.
func NewHTTPClient(timeout time.Duration, allowPrivate bool) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &guardedTransport{
			allowPrivate: allowPrivate,
			inner:        netguard.Transport(allowPrivate),
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("connectorauth: stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
}

func validateURL(u *url.URL, allowPrivate bool) error {
	if u.Host == "" {
		return errors.New("connectorauth: endpoint URL has no host")
	}
	if u.User != nil {
		return errors.New("connectorauth: endpoint URL must not carry credentials")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowPrivate {
			return nil
		}
		return fmt.Errorf("connectorauth: endpoint %q is not https; set security.allow_private_connector_endpoints=true to allow a plaintext vendor on the private network", u.Redacted())
	default:
		return fmt.Errorf("connectorauth: endpoint %q has an unsupported scheme %q", u.Redacted(), u.Scheme)
	}
}

// guardedTransport checks the URL of every request it is asked to make,
// which includes each redirect the client follows.
type guardedTransport struct {
	allowPrivate bool
	inner        http.RoundTripper
}

func (g *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := validateURL(req.URL, g.allowPrivate); err != nil {
		return nil, err
	}
	resp, err := g.inner.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("connectorauth: %s %s: %w", req.Method, req.URL.Redacted(), err)
	}
	return resp, nil
}
