// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// signup_residuals_test.go — the three properties this surface leans on that
// were previously unenforced: what a client_ip claim can buy, what a customer
// id must be bound to, and what an unauthenticated caller can occupy in Redis.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// client_ip
// ---------------------------------------------------------------------------

// TestNormalizeSignupClientIP_ArbitraryTextCannotMintBuckets is the reason
// normalization exists. The field is caller-supplied and the daemon cannot
// verify it — but it used to reach the key builder as raw text, so a caller
// minted a fresh per-IP budget for every string it felt like sending. Anything
// that is not an address now shares the one small unattributed bucket.
func TestNormalizeSignupClientIP_ArbitraryTextCannotMintBuckets(t *testing.T) {
	notAddresses := []string{"a", "b", "unknown", "203.0.113.7, 198.51.100.4", "999.1.1.1", " 203.0.113.7", ""}

	unattributed := signupIPKey("sv", normalizeSignupClientIP("a"))
	for _, raw := range notAddresses {
		require.Empty(t, normalizeSignupClientIP(raw), "%q is not an address and must be unattributed", raw)
		require.Equal(t, unattributed, signupIPKey("sv", normalizeSignupClientIP(raw)),
			"%q must land in the shared unattributed bucket, not a bucket of its own", raw)
	}
	require.Contains(t, unattributed, "unattributed")
}

// TestNormalizeSignupClientIP_OneAddressIsOneBucket closes the other half: a
// caller could re-spell its own address and get a fresh allowance each time.
func TestNormalizeSignupClientIP_OneAddressIsOneBucket(t *testing.T) {
	sameV4 := []string{"203.0.113.7", "::ffff:203.0.113.7"}
	first := signupIPKey("sv", normalizeSignupClientIP(sameV4[0]))
	for _, raw := range sameV4[1:] {
		require.Equal(t, first, signupIPKey("sv", normalizeSignupClientIP(raw)),
			"%q is the same destination as %q and must share its budget", raw, sameV4[0])
	}

	sameV6 := []string{"2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::1"}
	firstV6 := signupIPKey("sv", normalizeSignupClientIP(sameV6[0]))
	for _, raw := range sameV6[1:] {
		require.Equal(t, firstV6, signupIPKey("sv", normalizeSignupClientIP(raw)),
			"%q is the same destination as %q and must share its budget", raw, sameV6[0])
	}

	// Different addresses must still be different buckets, or the whole
	// per-IP scheme collapses into one.
	require.NotEqual(t, first, firstV6)
	require.NotEqual(t, first, signupIPKey("sv", normalizeSignupClientIP("198.51.100.4")))
}

// TestSignupLimits_EveryRPCHasAPeerIndependentBudget is the property that
// survives forgery. client_ip cannot be attributed here, so each RPC must also
// draw on a budget that the field cannot influence at all — otherwise forging
// it buys an unbounded allowance rather than a different bucket.
func TestSignupLimits_EveryRPCHasAPeerIndependentBudget(t *testing.T) {
	sets := map[string][]signupLimit{
		"RequestEmailVerification": requestVerificationLimits("a@b.c", "203.0.113.7"),
		"RedeemEmailVerification":  redeemLimits("203.0.113.7"),
		"Signup":                   completeLimits("203.0.113.7"),
	}
	for rpc, limits := range sets {
		t.Run(rpc, func(t *testing.T) {
			var global *signupLimit
			for i := range limits {
				if strings.HasSuffix(limits[i].key, ":global") {
					global = &limits[i]
				}
			}
			require.NotNil(t, global, "%s has no budget independent of client_ip", rpc)
			require.Positive(t, global.window.Max)

			// The claim must not reach the peer-independent key, or it is not
			// peer-independent.
			forged := map[string][]signupLimit{
				"RequestEmailVerification": requestVerificationLimits("a@b.c", "198.51.100.4"),
				"RedeemEmailVerification":  redeemLimits("198.51.100.4"),
				"Signup":                   completeLimits("198.51.100.4"),
			}[rpc]
			var forgedGlobal string
			for _, l := range forged {
				if strings.HasSuffix(l.key, ":global") {
					forgedGlobal = l.key
				}
			}
			require.Equal(t, global.key, forgedGlobal,
				"%s: changing client_ip moved the shared bucket, so it is not shared", rpc)

			// And it must be charged LAST, after every narrower budget, so a
			// request refused by a narrower one has not already spent it.
			require.Equal(t, global.key, limits[len(limits)-1].key,
				"%s charges the shared bucket before a narrower budget could refuse", rpc)
		})
	}
}

// TestSignupLimits_ForgedClientIPStillSpendsTheSharedBudget walks the property
// through the limiter rather than asserting on the key set: a caller that
// names a different address on every call gets a different per-IP bucket every
// time — that part is not fixable here — but each of those calls still charges
// the one budget that does not depend on the claim.
func TestSignupLimits_ForgedClientIPStillSpendsTheSharedBudget(t *testing.T) {
	rec := &recordingLimiter{}
	s := &DaemonServer{logger: testSlogLogger}
	s.signupLimiter = rec

	claims := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	for _, claim := range claims {
		require.NoError(t, s.checkSignupLimits(context.Background(), completeLimits(claim)...))
	}

	shared := 0
	for _, key := range rec.keys {
		if strings.HasSuffix(key, ":global") {
			shared++
		}
	}
	require.Equal(t, len(claims), shared,
		"every call must charge the shared budget, whatever address it claims")
}

// ---------------------------------------------------------------------------
// AttachSignupCustomer
// ---------------------------------------------------------------------------
