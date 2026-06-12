package reconciler

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/zeroroot-ai/sdk/auth"
)

// PrincipalMinter is the narrow contract the connector reconciler needs to
// create and destroy a per-launch capability-grant principal. It is satisfied
// by the same Zitadel principal client RegisterPlugin uses
// (admin.ZitadelPluginPrincipalClient).
type PrincipalMinter interface {
	CreatePrincipal(ctx context.Context, tenant auth.TenantID, installID, name string, ttl time.Duration) (principalID, bootstrapToken string, expiresAt time.Time, err error)
	DeletePrincipal(ctx context.Context, principalID string) error
}

// PrincipalIdentityMinter adapts a PrincipalMinter to the reconciler's
// IdentityMinter: each enable mints a fresh single-use bootstrap token + a
// (tenant, connector) principal, and a rolled-back launch deletes it. Mirrors
// the register-path identity lifecycle so a failed launch never leaks a
// principal. Satisfies IdentityMinter.
type PrincipalIdentityMinter struct {
	Minter PrincipalMinter
	// TTL is the bootstrap-token lifetime (≤24h per Spec 2 R3.1). Zero
	// defaults to one hour.
	TTL time.Duration
}

// MintConnectorPrincipal creates a (tenant, connector) principal + single-use
// bootstrap token. A fresh install id per mint keeps each launch's identity
// distinct, matching the register path.
func (m PrincipalIdentityMinter) MintConnectorPrincipal(ctx context.Context, tenant auth.TenantID, connector string) (string, string, error) {
	ttl := m.TTL
	if ttl == 0 {
		ttl = time.Hour
	}
	installID := uuid.NewString()
	principalID, token, _, err := m.Minter.CreatePrincipal(ctx, tenant, installID, connector, ttl)
	if err != nil {
		return "", "", err
	}
	return principalID, token, nil
}

// RevokeConnectorPrincipal deletes a principal minted for a launch that then
// failed, so a torn-down connector cannot re-enroll.
func (m PrincipalIdentityMinter) RevokeConnectorPrincipal(ctx context.Context, principalID string) error {
	return m.Minter.DeletePrincipal(ctx, principalID)
}
