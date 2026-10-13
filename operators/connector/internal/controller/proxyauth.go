// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// ProxyAuth is how the ToolHive proxy of a connector authenticates its
// caller. The daemon is the only caller (ADR-0114, D22). It presents a
// JWT-SVID with the audience connectorv1alpha1.ProxyAudience. The proxy
// validates the token against the SPIRE OIDC issuer and its JWKS, and a
// Cedar policy permits only the SPIFFE ID of the daemon. A call with no
// token, a token for another audience, or a token of another workload is
// refused.
type ProxyAuth struct {
	// Issuer is the SPIRE OIDC issuer, the iss claim of a JWT-SVID.
	Issuer string
	// JWKSURL is the address of the JWKS of that issuer.
	JWKSURL string
	// DaemonSPIFFEID is the SPIFFE ID of the daemon, the sub claim of its
	// JWT-SVID.
	DaemonSPIFFEID string
}

// errProxyAuthIncomplete is returned when a value of ProxyAuth is empty. The
// operator then makes no proxy, so no connector runs without caller
// authentication.
var errProxyAuthIncomplete = errors.New(
	"the proxy caller authentication needs the OIDC issuer, the JWKS URL and the daemon SPIFFE ID")

// validate reports errProxyAuthIncomplete when a value is empty, and an
// error when the JWKS URL names no service of the cluster.
func (a ProxyAuth) validate() error {
	if a.Issuer == "" || a.JWKSURL == "" || a.DaemonSPIFFEID == "" {
		return errProxyAuthIncomplete
	}
	_, err := a.IssuerNamespace()
	return err
}

// IssuerNamespace is the namespace of the SPIRE OIDC provider. The JWKS URL
// names its Service as <service>.<namespace>.svc, with or without the
// cluster domain. The proxy egress rule and the trust bundle copy both need
// this namespace, so a JWKS URL in another form is refused.
func (a ProxyAuth) IssuerNamespace() (string, error) {
	u, err := url.Parse(a.JWKSURL)
	if err != nil {
		return "", fmt.Errorf("the JWKS URL %q does not parse: %w", a.JWKSURL, err)
	}
	labels := strings.Split(u.Hostname(), ".")
	if len(labels) < 3 || labels[0] == "" || labels[1] == "" || labels[2] != "svc" {
		return "", fmt.Errorf(
			"the JWKS URL %q must name the SPIRE OIDC provider as <service>.<namespace>.svc", a.JWKSURL)
	}
	return labels[1], nil
}

// oidcConfig is the ToolHive oidcConfig of the proxy of ci: an inline
// issuer, JWKS and audience. The JWKS of the issuer is served inside the
// cluster, so a private address is permitted. The provider serves its SPIRE
// X.509-SVID, which no public root signs, so the proxy verifies it with the
// SPIRE trust bundle that the operator copies beside the connector
// (issuertrust.go).
func (a ProxyAuth) oidcConfig(ci *connectorv1alpha1.ConnectorInstance) map[string]interface{} {
	return map[string]interface{}{
		"type": "inline",
		"inline": map[string]interface{}{
			"issuer":             a.Issuer,
			"jwksUrl":            a.JWKSURL,
			"audience":           connectorv1alpha1.ProxyAudience,
			"jwksAllowPrivateIP": true,
			"caBundleRef": map[string]interface{}{
				"configMapRef": map[string]interface{}{
					"name": issuerCAName(ci),
					"key":  issuerCAKey,
				},
			},
		},
	}
}

// authzConfig is the ToolHive authzConfig of the proxy. ToolHive names the
// caller Client::<sub>, and the sub of a JWT-SVID is the SPIFFE ID. The one
// policy permits the daemon, so a valid token of another workload of the
// trust domain is refused.
func (a ProxyAuth) authzConfig() map[string]interface{} {
	return map[string]interface{}{
		"type": "inline",
		"inline": map[string]interface{}{
			"policies": []interface{}{
				"permit(principal == Client::" + strconv.Quote(a.DaemonSPIFFEID) + ", action, resource);",
			},
			"entitiesJson": "[]",
		},
	}
}
