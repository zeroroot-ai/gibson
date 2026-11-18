// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// ErrNoMissionScope is the answer of the grant source for a call that has no
// mission or no task. A Capability Grant names one tenant, one mission and one
// task, and ext-authz refuses a grant without them. The epic gives no identity
// for a daemon call outside a mission.
var ErrNoMissionScope = errors.New("modelclient: the call has no mission and no task, so it has no grant")

// grantTTL is the lifetime of the grant of one call. A call is short, and the
// grant is minted for it alone.
const grantTTL = 5 * time.Minute

// Minter is the part of the daemon signer that the grant source needs.
type Minter interface {
	Mint(req capabilitygrant.MintRequest) (string, error)
}

// MinterGrants signs the grant of a daemon call with the signing key of the
// daemon. It is the same Minter that signs the grant of a dispatched task, so
// ext-authz verifies it with the same rule: the tenant, the mission and the task
// are signed claims, the listed routes are the model routes, and the grant
// expires.
type MinterGrants struct {
	minter Minter
	routes []string
}

// NewMinterGrants returns a grant source over the daemon signer. The grant lists
// the model routes of modelcall.GrantRoutes and the list route, because the
// daemon lists the models of a provider with its own identity.
func NewMinterGrants(m Minter) (*MinterGrants, error) {
	if m == nil {
		return nil, errors.New("modelclient: the signer is required")
	}
	routes := append(modelcall.GrantRoutes(), modelcall.RouteModels)
	return &MinterGrants{minter: m, routes: routes}, nil
}

// Grant signs the grant of one call.
func (g *MinterGrants) Grant(_ context.Context, c Caller) (string, error) {
	if c.Mission == "" || c.Task == "" {
		return "", ErrNoMissionScope
	}
	if c.Purpose == "" {
		return "", errors.New("modelclient: the caller has no purpose")
	}
	tok, err := g.minter.Mint(capabilitygrant.MintRequest{
		Subject:        "component:daemon:" + c.Purpose,
		Tenant:         c.Tenant,
		MissionID:      c.Mission,
		TaskID:         c.Task,
		Initiator:      c.Initiator,
		AllowedRPCs:    g.routes,
		TTL:            grantTTL,
		RecipientClass: "agent",
	})
	if err != nil {
		return "", fmt.Errorf("mint the grant of %s: %w", c.Purpose, err)
	}
	return tok, nil
}
