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

// ErrNoGrantScope is the answer of the grant source for a call that has neither a
// mission and a task, nor a purpose of a daemon call grant.
var ErrNoGrantScope = errors.New("modelclient: the call has no mission and no daemon call purpose, so it has no grant")

// grantTTL is the lifetime of the grant of one call. A call is short, and the
// grant is minted for it alone.
const grantTTL = 5 * time.Minute

// Minter is the part of the daemon signer that the grant source needs.
type Minter interface {
	Mint(req capabilitygrant.MintRequest) (string, error)
	MintDaemonCall(req capabilitygrant.DaemonCallRequest) (string, error)
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

// Grant signs the grant of one call. A call of a mission gets a task grant. A
// call with no mission gets a daemon call grant: it lasts 60 seconds, names one
// route, and its purpose is one of the closed set (embedding, chat,
// provider_probe, model_list). A chat call needs the initiator.
func (g *MinterGrants) Grant(_ context.Context, c Caller) (string, error) {
	if c.Purpose == "" {
		return "", errors.New("modelclient: the caller has no purpose")
	}
	if c.Mission == "" && c.Task == "" {
		if _, ok := modelcall.PurposeRoute(c.Purpose); !ok {
			return "", fmt.Errorf("%w: %q", ErrNoGrantScope, c.Purpose)
		}
		tok, err := g.minter.MintDaemonCall(capabilitygrant.DaemonCallRequest{
			Tenant: c.Tenant, Purpose: c.Purpose, Initiator: c.Initiator,
		})
		if err != nil {
			return "", fmt.Errorf("mint the daemon call grant of %s: %w", c.Purpose, err)
		}
		return tok, nil
	}
	if c.Mission == "" || c.Task == "" {
		return "", ErrNoGrantScope
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
