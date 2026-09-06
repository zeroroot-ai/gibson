// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// SPIFFE-SVID plugin enrollment (ADR-0066).
//
// A first-party, in-cluster plugin proves its FIRST capability-grant
// registration with its SPIRE JWT-SVID instead of a human-minted bootstrap
// token. The SDK fetches a JWT-SVID whose audience is the register URL and
// presents it as the register `Authorization: Bearer`. This file verifies that
// SVID against the SPIRE JWT bundle, maps it to a first-party plugin identity,
// and provisions the plugin principal. Registration itself reuses the shared
// RegisterCapabilityGrant path in the register handler.

// pluginSVIDPathPrefix is the SPIFFE ID path a first-party plugin is issued:
// spiffe://<trust-domain>/plugin/<vendor> (the chart's per-plugin
// ClusterSPIFFEID, ADR-0066).
const pluginSVIDPathPrefix = "/plugin/"

// pluginVendorRe bounds the vendor segment parsed from a plugin SVID's SPIFFE ID
// path. It matches the agent-identity name rule. SPIRE issues the SVID (the
// vendor is not attacker-controlled input), but the vendor becomes an FGA object
// id and a component name, so it is validated defensively.
var pluginVendorRe = regexp.MustCompile(`^[a-z][a-z0-9-]{2,40}$`)

// ErrSVIDUnverified is returned when a register credential is not a valid,
// audience-bound plugin JWT-SVID from the trusted domain. The register handler
// maps it to a generic 401 so no verification detail leaks to the caller.
var ErrSVIDUnverified = errors.New("capability-grant: SVID enrollment: credential is not a valid plugin SVID")

// pluginSVIDIdentity is the first-party plugin identity a verified SVID resolves
// to. It is the exact set the shared RegisterCapabilityGrant path needs.
type pluginSVIDIdentity struct {
	TenantID     string
	OwnerUserID  string
	PrincipalRef string
	Name         string
}

// pluginEnroller is the register handler's view of SPIFFE-SVID plugin
// enrollment. It is nil when the daemon has no SPIRE JWT source or no configured
// install-tenant binding, in which case the register handler never takes the
// SVID branch.
type pluginEnroller interface {
	// ResolvePluginBySVID verifies token as a plugin JWT-SVID whose audience must
	// be registerURL, provisions the plugin principal idempotently, and returns
	// the resolved identity. It returns an error wrapping ErrSVIDUnverified for
	// any credential that is not a valid plugin SVID.
	ResolvePluginBySVID(ctx context.Context, token, registerURL string) (*pluginSVIDIdentity, error)
}

// spiffePluginEnroller verifies plugin JWT-SVIDs and provisions their identity.
type spiffePluginEnroller struct {
	bundles     jwtbundle.Source
	trustDomain spiffeid.TrustDomain
	cg          pluginProvisioner
	tenantID    string
	logger      *slog.Logger
}

// pluginProvisioner idempotently provisions a first-party plugin's FGA identity
// and returns its principal reference. Satisfied by
// *capabilitygrant.CapabilityGrantService; an interface so the verifier can be
// tested without a full service.
type pluginProvisioner interface {
	ProvisionPluginPrincipal(ctx context.Context, vendor, tenantID string) (principalRef, ownerUserID string, err error)
}

// ResolvePluginBySVID implements pluginEnroller.
func (e *spiffePluginEnroller) ResolvePluginBySVID(ctx context.Context, token, registerURL string) (*pluginSVIDIdentity, error) {
	// jwtsvid.ParseAndValidate checks the signature against the SPIRE JWT bundle
	// (trust-domain scoped), the expiry, and that registerURL is in the audience
	// — the same URL the SDK bound the SVID to. A per-RPC CG-JWT or a bootstrap
	// token cannot pass: it is not signed by SPIRE.
	svid, err := jwtsvid.ParseAndValidate(token, e.bundles, []string{registerURL})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSVIDUnverified, err)
	}
	if svid.ID.TrustDomain() != e.trustDomain {
		return nil, fmt.Errorf("%w: unexpected trust domain %q", ErrSVIDUnverified, svid.ID.TrustDomain())
	}
	vendor, err := pluginVendorFromSPIFFEID(svid.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSVIDUnverified, err)
	}

	principalRef, ownerUserID, err := e.cg.ProvisionPluginPrincipal(ctx, vendor, e.tenantID)
	if err != nil {
		// A provisioning failure is an internal fault, not an unverified
		// credential. Wrap it (NOT with ErrSVIDUnverified) so the handler's
		// errors.Is(ErrSVIDUnverified) is false and it answers 500, not 401.
		return nil, fmt.Errorf("provision plugin principal: %w", err)
	}

	e.logger.InfoContext(ctx, "capability-grant: SPIFFE-SVID plugin enrollment verified",
		slog.String("spiffe_id", svid.ID.String()),
		slog.String("principal", principalRef),
		slog.String("tenant_id", e.tenantID),
	)
	return &pluginSVIDIdentity{
		TenantID:     e.tenantID,
		OwnerUserID:  ownerUserID,
		PrincipalRef: principalRef,
		Name:         vendor,
	}, nil
}

// pluginVendorFromSPIFFEID extracts and validates the vendor segment from a
// first-party plugin's SPIFFE ID (spiffe://<td>/plugin/<vendor>).
func pluginVendorFromSPIFFEID(id spiffeid.ID) (string, error) {
	p := id.Path()
	if !strings.HasPrefix(p, pluginSVIDPathPrefix) {
		return "", fmt.Errorf("SPIFFE ID path %q is not a plugin identity (want %s<vendor>)", p, pluginSVIDPathPrefix)
	}
	vendor := strings.TrimPrefix(p, pluginSVIDPathPrefix)
	if !pluginVendorRe.MatchString(vendor) {
		return "", fmt.Errorf("plugin vendor %q in SPIFFE ID is not a valid component name", vendor)
	}
	return vendor, nil
}
