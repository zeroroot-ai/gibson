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

// SPIFFE-SVID plugin enrollment (ADR-0066), one instance for each tenant
// (gibson#815).
//
// A catalog plugin runs as one instance for each tenant that enabled it. The
// tenant operator gives each instance the SPIFFE ID
// spiffe://<trust-domain>/plugin/<vendor>/<tenant>. The instance proves its
// FIRST capability-grant registration with its SPIRE JWT-SVID instead of a
// human-minted bootstrap token. This file verifies that SVID against the SPIRE
// JWT bundle, reads the plugin and the tenant from its path, checks that the
// tenant enabled the plugin, and provisions the principal of that one
// instance. Registration itself reuses the shared RegisterCapabilityGrant path
// in the register handler.
//
// The daemon accepts no other path form for a plugin. In particular it
// refuses the form /plugin/<vendor> of the time when one instance served the
// whole install, and the generic form ns/<namespace>/sa/<name> that SPIRE can
// give to any other pod.

// pluginSVIDPathPrefix starts the SPIFFE ID path of a plugin instance.
const pluginSVIDPathPrefix = "/plugin/"

// pluginVendorRe bounds the vendor segment parsed from a plugin SVID's SPIFFE ID
// path. It matches the agent-identity name rule. SPIRE issues the SVID (the
// vendor is not attacker-controlled input), but the vendor becomes an FGA object
// id and a component name, so it is validated defensively.
var pluginVendorRe = regexp.MustCompile(`^[a-z][a-z0-9-]{2,40}$`)

// pluginTenantRe bounds the tenant segment. It is the rule of the tenant
// operator for a tenant that can have a plugin namespace: a DNS label. The
// tenant becomes a part of an FGA object id, so a dot, a slash and a colon
// never pass.
var pluginTenantRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$`)

// ErrSVIDUnverified is returned when a register credential is not a valid,
// audience-bound plugin JWT-SVID from the trusted domain. The register handler
// maps it to a generic 401 so no verification detail leaks to the caller.
var ErrSVIDUnverified = errors.New("capability-grant: SVID enrollment: credential is not a valid plugin SVID")

// pluginSVIDIdentity is the plugin instance identity a verified SVID resolves
// to. It is the exact set the shared RegisterCapabilityGrant path needs.
type pluginSVIDIdentity struct {
	TenantID     string
	OwnerUserID  string
	PrincipalRef string
	Name         string
}

// pluginEnroller is the register handler's view of SPIFFE-SVID plugin
// enrollment. It is nil when the daemon has no SPIRE JWT source, in which case
// the register handler never takes the SVID branch.
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
	enabled     pluginEnablement
	logger      *slog.Logger
}

// pluginProvisioner idempotently provisions the FGA identity of one plugin
// instance and returns its principal reference. Satisfied by
// *capabilitygrant.CapabilityGrantService; an interface so the verifier can be
// tested without a full service. The first argument is the name of the
// principal, which is distinct for each (plugin, tenant) pair.
type pluginProvisioner interface {
	ProvisionPluginPrincipal(ctx context.Context, principalName, tenantID string) (principalRef, ownerUserID string, err error)
}

// pluginEnablement answers whether a tenant enabled a catalog plugin.
// Satisfied by *catalogplugin.Store.
type pluginEnablement interface {
	IsEnabled(ctx context.Context, tenantID, pluginID string) (bool, error)
}

// pluginInstancePrincipalName is the principal name of the instance of vendor
// for tenant. One principal for all tenants would be a member of every tenant,
// so each instance has its own. Neither part can hold a dot (pluginVendorRe,
// pluginTenantRe), so two different pairs never give the same name.
func pluginInstancePrincipalName(vendor, tenant string) string {
	return vendor + "." + tenant
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
	vendor, tenantID, err := pluginInstanceFromSPIFFEID(svid.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSVIDUnverified, err)
	}

	// The identity is valid only while the tenant wants the plugin. A read
	// error is an internal fault (500), never a reason to accept.
	enabled, err := e.enabled.IsEnabled(ctx, tenantID, vendor)
	if err != nil {
		return nil, fmt.Errorf("check that tenant %q enabled plugin %q: %w", tenantID, vendor, err)
	}
	if !enabled {
		return nil, fmt.Errorf("%w: tenant %q did not enable plugin %q", ErrSVIDUnverified, tenantID, vendor)
	}

	principalRef, ownerUserID, err := e.cg.ProvisionPluginPrincipal(ctx, pluginInstancePrincipalName(vendor, tenantID), tenantID)
	if err != nil {
		// A provisioning failure is an internal fault, not an unverified
		// credential. Wrap it (NOT with ErrSVIDUnverified) so the handler's
		// errors.Is(ErrSVIDUnverified) is false and it answers 500, not 401.
		return nil, fmt.Errorf("provision plugin principal: %w", err)
	}

	e.logger.InfoContext(ctx, "capability-grant: SPIFFE-SVID plugin enrollment verified",
		slog.String("spiffe_id", svid.ID.String()),
		slog.String("principal", principalRef),
		slog.String("tenant_id", tenantID),
	)
	return &pluginSVIDIdentity{
		TenantID:     tenantID,
		OwnerUserID:  ownerUserID,
		PrincipalRef: principalRef,
		Name:         vendor,
	}, nil
}

// pluginInstanceFromSPIFFEID reads the vendor and the tenant from the SPIFFE
// ID of a plugin instance, spiffe://<td>/plugin/<vendor>/<tenant>. It refuses
// each other form.
func pluginInstanceFromSPIFFEID(id spiffeid.ID) (vendor, tenant string, err error) {
	p := id.Path()
	if !strings.HasPrefix(p, pluginSVIDPathPrefix) {
		return "", "", fmt.Errorf("SPIFFE ID path %q is not a plugin identity (want %s<vendor>/<tenant>)", p, pluginSVIDPathPrefix)
	}
	segments := strings.Split(strings.TrimPrefix(p, pluginSVIDPathPrefix), "/")
	if len(segments) != 2 {
		return "", "", fmt.Errorf("SPIFFE ID path %q is not a plugin instance (want %s<vendor>/<tenant>)", p, pluginSVIDPathPrefix)
	}
	vendor, tenant = segments[0], segments[1]
	if !pluginVendorRe.MatchString(vendor) {
		return "", "", fmt.Errorf("plugin vendor %q in SPIFFE ID is not a valid component name", vendor)
	}
	if !pluginTenantRe.MatchString(tenant) {
		return "", "", fmt.Errorf("tenant %q in SPIFFE ID is not a valid tenant name", tenant)
	}
	return vendor, tenant, nil
}
