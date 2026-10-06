// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"errors"
	"strconv"

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

// validate reports errProxyAuthIncomplete when a value is empty.
func (a ProxyAuth) validate() error {
	if a.Issuer == "" || a.JWKSURL == "" || a.DaemonSPIFFEID == "" {
		return errProxyAuthIncomplete
	}
	return nil
}

// oidcConfig is the ToolHive oidcConfig of the proxy: an inline issuer,
// JWKS and audience. The JWKS of the issuer is served inside the cluster, so
// a private address is permitted.
func (a ProxyAuth) oidcConfig() map[string]interface{} {
	return map[string]interface{}{
		"type": "inline",
		"inline": map[string]interface{}{
			"issuer":             a.Issuer,
			"jwksUrl":            a.JWKSURL,
			"audience":           connectorv1alpha1.ProxyAudience,
			"jwksAllowPrivateIP": true,
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
