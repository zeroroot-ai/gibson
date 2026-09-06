// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — brain_worldview.go
//
// worldViewSource is the read complement of ingestObservation: where the
// Observe RPC folds an agent's writes into the tenant World, the WorldView RPC
// projects a mission-Scope-limited slice of that World back to the agent
// (ADR-0012, the emit-only contract's read half; gibson#1377).
//
// The projection is server-authored end to end. The agent never names a brain
// id: every entity is issued an opaque, server-minted handle it cannot
// construct or iterate, so a slice cannot be enumerated past its boundary. The
// tenant and scope are the daemon's, read off the mission record by the
// callback service before this source is called — the agent supplies neither.
package daemon

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// worldViewProjectionCap bounds one slice. It is a server-side budget, not a
// caller-tunable limit; a slice that exceeds it is truncated and reported as
// such (WorldViewResponse.truncated), never widened on request.
const worldViewProjectionCap = 200

// handleMinter mints the opaque handles that name entities in a World slice.
//
// A handle is HMAC(key, scope || kind || brainID) rendered base64url. That makes
// it:
//   - non-constructible — the key never leaves the daemon, so an agent cannot
//     forge a handle for an entity it was not shown;
//   - non-iterable — it carries no brain id an agent could increment to walk the
//     World past its slice;
//   - stable across re-projections — the inputs are fixed for the life of the
//     entity, so refreshing a slice never invalidates a handle the agent holds
//     (harness_callback.proto's WorldEntity contract).
//
// The key is process-random: handles need be stable only within a mission's
// lifetime, and the brain World is itself in-memory per process, so there is no
// cross-restart handle to preserve.
type handleMinter struct {
	key []byte
}

func newHandleMinter() (*handleMinter, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("world-view handle key: %w", err)
	}
	return &handleMinter{key: key}, nil
}

// mint derives the handle for one entity. scope binds the handle to the caller's
// slice; kind + brainID identify the entity within it. brainID is a string so
// both the uint64 ids (hosts, domains, …) and the string finding ids share one
// path.
func (m *handleMinter) mint(scope string, kind harnesspb.WorldEntityKind, brainID string) string {
	mac := hmac.New(sha256.New, m.key)
	// Length-prefix each field so ("a","b") and ("ab","") cannot collide.
	_, _ = fmt.Fprintf(mac, "%d:%s|%d|%s", len(scope), scope, int32(kind), brainID)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:18])
}

// worldViewSource returns the harness WorldViewSource wired to the per-tenant
// brain. reg is the brain registry; minter supplies the handle key.
//
// Projection is level-of-detail: the unfocused slice carries a compact summary
// per entity; a focused slice returns the named entities at full detail. focus
// can only ever zoom into the slice the caller already holds — a focus handle
// that this source did not mint for this (scope) is refused with
// codes.PermissionDenied, so focus can never widen a slice or reach another
// mission's entities.
func worldViewSource(reg *brain.Registry, minter *handleMinter) harness.WorldViewSource {
	return func(_ context.Context, q harness.WorldViewQuery) (harness.WorldViewResult, error) {
		if reg == nil {
			return harness.WorldViewResult{}, nil
		}
		eng := reg.For(q.Tenant)

		focus := make(map[string]bool, len(q.Focus))
		for _, h := range q.Focus {
			focus[h] = true
		}
		full := len(focus) > 0

		var all []harness.WorldEntityRecord
		emit := func(kind harnesspb.WorldEntityKind, brainID, label string, attrs map[string]string) {
			all = append(all, harness.WorldEntityRecord{
				Handle:     minter.mint(q.ScopeID, kind, brainID),
				Kind:       kind,
				Label:      label,
				Attributes: attrs,
			})
		}

		for _, h := range eng.Hosts() {
			if h.ScopeID != q.ScopeID {
				continue
			}
			emit(harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_HOST,
				strconv.FormatUint(h.ID, 10), h.Address, hostAttributes(h, full))
		}
		for _, d := range eng.Domains() {
			if d.ScopeID != q.ScopeID {
				continue
			}
			emit(harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_DOMAIN,
				strconv.FormatUint(d.ID, 10), d.Name, nil)
		}
		for _, sd := range eng.Subdomains() {
			if sd.ScopeID != q.ScopeID {
				continue
			}
			emit(harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_SUBDOMAIN,
				strconv.FormatUint(sd.ID, 10), sd.FQDN, subdomainAttributes(sd, full))
		}
		for _, c := range eng.Credentials() {
			if c.ScopeID != q.ScopeID {
				continue
			}
			emit(harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_CREDENTIAL,
				strconv.FormatUint(c.ID, 10), credentialLabel(c), credentialAttributes(c, full))
		}
		for _, a := range eng.Accounts() {
			if a.ScopeID != q.ScopeID {
				continue
			}
			emit(harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_ACCOUNT,
				strconv.FormatUint(a.ID, 10), a.Identifier, accountAttributes(a, full))
		}
		for _, f := range eng.Findings() {
			if f.ScopeID != q.ScopeID {
				continue
			}
			emit(harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_FINDING,
				f.ID, f.Title, findingAttributes(f, full))
		}

		if full {
			return focusSlice(all, focus)
		}
		return capSlice(all), nil
	}
}

// focusSlice returns only the requested entities, at full detail. A focus handle
// that names no entity in this slice was never issued to this caller — refuse it
// (codes.PermissionDenied) rather than silently dropping it, so focus can only
// zoom into an already-held slice, never probe for handles.
func focusSlice(all []harness.WorldEntityRecord, focus map[string]bool) (harness.WorldViewResult, error) {
	byHandle := make(map[string]harness.WorldEntityRecord, len(all))
	for _, e := range all {
		byHandle[e.Handle] = e
	}
	out := make([]harness.WorldEntityRecord, 0, len(focus))
	// Deterministic order: iterate the projected slice, not the request map.
	for _, e := range all {
		if focus[e.Handle] {
			out = append(out, e)
		}
	}
	for h := range focus {
		if _, ok := byHandle[h]; !ok {
			return harness.WorldViewResult{}, status.Errorf(codes.PermissionDenied,
				"focus handle %q was not issued to this slice", h)
		}
	}
	// A focused slice is bounded by the request, but still cap it: a caller
	// cannot raise the budget by listing more handles than the cap.
	return capSlice(out), nil
}

// capSlice enforces the projection budget, reporting truncation.
func capSlice(all []harness.WorldEntityRecord) harness.WorldViewResult {
	if len(all) <= worldViewProjectionCap {
		return harness.WorldViewResult{Entities: all}
	}
	return harness.WorldViewResult{Entities: all[:worldViewProjectionCap], Truncated: true}
}

func hostAttributes(h brain.HostSnapshot, full bool) map[string]string {
	attrs := map[string]string{"open_ports": strconv.Itoa(len(h.OpenPorts))}
	if h.Surprise != "" {
		attrs["surprise"] = h.Surprise
	}
	if !full {
		return attrs
	}
	if len(h.OpenPorts) > 0 {
		ports := make([]string, len(h.OpenPorts))
		for i, p := range h.OpenPorts {
			ports[i] = strconv.Itoa(p)
		}
		attrs["ports"] = strings.Join(ports, ",")
	}
	if svc := servicePortLabels(h); svc != "" {
		attrs["services"] = svc
	}
	if h.CloudID != "" {
		attrs["cloud_id"] = h.CloudID
	}
	return attrs
}

// servicePortLabels renders "port/name" pairs for ports that carry service
// detail, in ascending port order for determinism.
func servicePortLabels(h brain.HostSnapshot) string {
	ports := make([]int, 0, len(h.Services))
	for p := range h.Services {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		name := h.Services[p].Name
		if name == "" {
			name = h.Services[p].Protocol
		}
		parts = append(parts, fmt.Sprintf("%d/%s", p, name))
	}
	return strings.Join(parts, ",")
}

func subdomainAttributes(sd brain.SubdomainSnapshot, full bool) map[string]string {
	if !full {
		if len(sd.Addresses) == 0 {
			return nil
		}
		return map[string]string{"addresses": strconv.Itoa(len(sd.Addresses))}
	}
	attrs := map[string]string{"domain": sd.DomainName}
	if len(sd.Addresses) > 0 {
		attrs["addresses"] = strings.Join(sd.Addresses, ",")
	}
	return attrs
}

// credentialLabel names a credential by username without revealing the secret;
// the secret hash is never projected to the agent.
func credentialLabel(c brain.CredentialSnapshot) string {
	if c.Username != "" {
		return c.Username
	}
	return c.Kind
}

func credentialAttributes(c brain.CredentialSnapshot, full bool) map[string]string {
	if c.Kind == "" {
		return nil
	}
	attrs := map[string]string{"kind": c.Kind}
	if full && c.Username != "" {
		attrs["username"] = c.Username
	}
	return attrs
}

func accountAttributes(a brain.AccountSnapshot, _ bool) map[string]string {
	if a.Kind == "" {
		return nil
	}
	return map[string]string{"kind": a.Kind}
}

func findingAttributes(f brain.FindingSnapshot, full bool) map[string]string {
	attrs := map[string]string{}
	if f.Severity != "" {
		attrs["severity"] = f.Severity
	}
	if f.Address != "" {
		attrs["address"] = f.Address
	}
	if full && f.Description != "" {
		attrs["description"] = f.Description
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}
