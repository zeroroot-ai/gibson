// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package principal names who did something: a person, the tenant, a
// component run, or a platform service. Banks record their owner, jobs record
// who opened them and who sent each input, missions record who created them.
// One type, one wire shape (gibson.common.v1.Principal), one rule for reading
// a caller's class from its subject.
//
// A record carries the id, never a name (hosted#205). A reader resolves the
// id at read time through UserService.ResolveUsers, so a person who left the
// tenant shows as "removed user" and nothing copied at creation goes stale.
package principal

import (
	"strings"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// Kind is the class of a principal. It decides how to read ID.
type Kind string

// The principal kinds.
const (
	User      Kind = "user"
	Tenant    Kind = "tenant"
	Component Kind = "component"
	Service   Kind = "service"
)

// Principal is who did something.
type Principal struct {
	Kind Kind   `json:"kind,omitempty"`
	ID   string `json:"id,omitempty"`
}

// IsZero reports an unset principal, which is what a record created before
// attribution existed carries.
func (p Principal) IsZero() bool { return p.Kind == "" && p.ID == "" }

// Ref is the principal as one string, "<kind>:<id>", for a graph property or
// a log line. Empty for the zero principal.
func (p Principal) Ref() string {
	if p.IsZero() {
		return ""
	}
	return string(p.Kind) + ":" + p.ID
}

// typedSubjectPrefixes are the subjects that already name their class: a
// component's subject is a typed FGA principal (ADR-0045).
var typedSubjectPrefixes = []string{"agent_principal:", "tool_principal:", "plugin_principal:"}

// KindOf reads the class of a subject. A component's subject is a typed FGA
// principal; anything else is a person or a service account, and the two are
// told apart by the credential the identity carries, not by the subject, so
// a subject alone maps to User.
func KindOf(subject string) Kind {
	for _, prefix := range typedSubjectPrefixes {
		if strings.HasPrefix(subject, prefix) {
			return Component
		}
	}
	return User
}

// FGAUser is the FGA user reference for an identity: a typed principal ref
// unchanged, otherwise "user:<subject>" with a SPIFFE scheme stripped.
func FGAUser(id auth.Identity) string {
	for _, prefix := range append(typedSubjectPrefixes, "user:") {
		if strings.HasPrefix(id.Subject, prefix) {
			return id.Subject
		}
	}
	return "user:" + strings.TrimPrefix(id.Subject, "spiffe://")
}

// IDOf is the id a record stores for a caller: the FGA user without the
// "user:" type, and a typed principal ref unchanged. The tuple writers put
// "user:" back, so what a record writes is what authorize reads. Recording
// the raw subject instead wrote "user:spiffe://<id>" for a SPIFFE caller
// while every check asked for "user:<id>" (gibson#13, run 35443640498).
func IDOf(id auth.Identity) string {
	return strings.TrimPrefix(FGAUser(id), "user:")
}

// FromIdentity is the principal a record stores for the caller.
func FromIdentity(id auth.Identity) Principal {
	return Principal{Kind: KindOf(id.Subject), ID: IDOf(id)}
}

// ToProto renders a principal on the wire. The zero principal renders as
// nil, which a proto reader sees as "unset".
func ToProto(p Principal) *commonpb.Principal {
	if p.IsZero() {
		return nil
	}
	kind := commonpb.Principal_KIND_USER
	switch p.Kind {
	case Tenant:
		kind = commonpb.Principal_KIND_TENANT
	case Component:
		kind = commonpb.Principal_KIND_COMPONENT
	case Service:
		kind = commonpb.Principal_KIND_SERVICE
	case User:
		// The default above. Named so a new kind fails the exhaustive check
		// rather than quietly rendering as a person.
	}
	return &commonpb.Principal{Kind: kind, Id: p.ID}
}
