// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenant

import "strings"

// FoundingMemberName builds the founding-owner TenantMember CR name from the
// owner email. It is the ONE canonical derivation, byte-identical to the
// dashboard's `${slugify(email)}-owner` (app/actions/signup.ts), so a founding
// member created by the pending-provisioning reconcile, the dashboard, or the
// self-hosted first-admin bootstrap all resolve to the same CR name and
// converge idempotently rather than racing into two members.
func FoundingMemberName(email string) string {
	return SlugifyEmail(email) + "-owner"
}

// SlugifyEmail lowercases the email and replaces every rune that is not
// [a-z0-9-] with a dash, collapses runs of dashes, trims leading/trailing
// dashes, and caps the result at 63 bytes (DNS-label style). It mirrors the
// dashboard's slugify exactly.
func SlugifyEmail(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := collapseDashes(b.String())
	out = strings.Trim(out, "-")
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

// collapseDashes replaces every run of consecutive dashes with a single dash.
func collapseDashes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := false
	for i := range len(s) {
		if s[i] == '-' {
			if !prevDash {
				b.WriteByte('-')
			}
			prevDash = true
			continue
		}
		b.WriteByte(s[i])
		prevDash = false
	}
	return b.String()
}
