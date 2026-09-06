// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — signup_rate_limit.go
//
// Rate limiting for the unauthenticated self-serve signup surface.
//
// Two properties matter more than the specific numbers:
//
//  1. It lives in the daemon, inside the RPC handlers. The web tier has a
//     perfectly good Redis-backed limiter of its own, but a limiter there is a
//     callable pre-check: it binds only the entrypoints that remember to call
//     it, and it cannot bind a caller that reaches the RPC another way.
//     Enforcing inside the handler means there is no route to provisioning
//     that does not pass the same chokepoint. The web-tier limiter stays as a
//     cheap early reject; this one is the control.
//
//  2. It fails CLOSED. No limiter configured, or Redis unreachable, and the
//     request is refused with Unavailable. On an unauthenticated surface that
//     sends email and creates identities, "we cannot count, so proceed" is not
//     a degradation — it is the removal of the control.
//
// # What client_ip is worth
//
// Every per-IP budget here keys on the request's client_ip field, and that
// field is a claim, not an observation. The daemon cannot check it:
//
//   - The gRPC peer is the edge proxy for every call that arrives through
//     Envoy, so peer.FromContext yields the proxy's address, not the caller's.
//     Comparing client_ip to the peer would fail for real traffic and succeed
//     for none of it.
//   - The value the dashboard forwards is the leftmost X-Forwarded-For entry,
//     which the caller appends. Nothing between the caller and here overwrites
//     it, so it is caller-controlled end to end.
//
// So the per-IP budgets are best-effort shaping of honest traffic, and they
// are documented as such rather than described as a control. Making client_ip
// attributable is an edge change (Envoy use_remote_address plus a trusted-hop
// count matching the load-balancer chain, and the dashboard reading the
// resulting authoritative value), not a daemon change.
//
// Two things the daemon can still do, and does:
//
//   - Normalise the field, so it is at minimum a well-formed address in one
//     canonical spelling. See normalizeSignupClientIP.
//   - Give every signup RPC a budget that does not depend on client_ip at all,
//     so forging the field buys a smaller per-IP bucket and never an unbounded
//     one. RequestEmailVerification always had such a budget; the other three
//     RPCs did not, which meant a forged client_ip made them effectively
//     unlimited. They do now.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/ratelimit"
)

// Budgets for each signup surface. Every entry is a sliding window, so the
// hour and day budgets cannot both be spent across a bucket boundary.
var (
	// Request-verification budgets, per address. Low: a person needs one link,
	// occasionally two.
	signupRequestPerEmailHour = ratelimit.Window{Max: 3, Period: hour}
	signupRequestPerEmailDay  = ratelimit.Window{Max: 5, Period: day}

	// Request-verification budgets, per client IP. Generous enough for a
	// shared NAT, tight enough that one source cannot farm the mail sender.
	signupRequestPerIPHour = ratelimit.Window{Max: 10, Period: hour}
	signupRequestPerIPDay  = ratelimit.Window{Max: 30, Period: day}

	// Requests that arrive with no attributable client IP share one small
	// bucket. They are NOT folded into the normal per-IP limits under an
	// "unknown" key: that would hand an attacker a way to exhaust a bucket
	// that legitimate unattributed traffic also needs, and would give
	// unattributed traffic the same budget as attributed traffic.
	signupRequestUnattributedHour = ratelimit.Window{Max: 20, Period: hour}

	// Global circuit breaker. Protects the sending quota and the sender
	// reputation attached to it; tripping it is an alertable event.
	signupRequestGlobalHour = ratelimit.Window{Max: 300, Period: hour}

	// Redemption and completion. Redemption is cheap and idempotent-ish;
	// completion provisions, so it is tighter.
	signupRedeemPerIPHour   = ratelimit.Window{Max: 30, Period: hour}
	signupCompletePerIPHour = ratelimit.Window{Max: 10, Period: hour}

	// Attaching a billing customer to a live verified session. Loose, because a
	// legitimate card retry re-attaches, but bounded.
	signupAttachPerIPHour = ratelimit.Window{Max: 30, Period: hour}

	// Peer-independent budgets for the three RPCs that follow
	// RequestEmailVerification. These key on nothing the caller supplies, so
	// they are the only budget on this surface that forging client_ip cannot
	// step around.
	//
	// One number, matching signupRequestGlobalHour, and for the same reason it
	// cannot bind tighter than that gate already does: every redemption needs
	// a verification email, every completion needs a redemption, and
	// verification is capped at the same 300/hour. Legitimate traffic that
	// this refuses would have been refused one step earlier.
	signupRedeemGlobalHour   = ratelimit.Window{Max: 300, Period: hour}
	signupAttachGlobalHour   = ratelimit.Window{Max: 300, Period: hour}
	signupCompleteGlobalHour = ratelimit.Window{Max: 300, Period: hour}
)

const (
	hour = time.Hour
	day  = 24 * time.Hour
)

// signupLimit pairs a Redis key with the budget it draws from.
type signupLimit struct {
	key    string
	window ratelimit.Window
}

// hashForKey reduces an identifier to a short hash before it becomes a Redis
// key. Addresses and IPs of people who have not yet consented to anything
// should not sit in plaintext in a cache that operators routinely dump.
func hashForKey(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:32]
}

// normalizeSignupClientIP reduces the request's client_ip claim to either one
// canonical address string or "" (unattributed).
//
// It is not an authenticity check — see the package comment; nothing here can
// make the field attributable. It removes two properties the raw field had:
//
//   - Any string at all became a bucket key. "a", "b", "c" … minted unlimited
//     distinct per-IP budgets, so the per-IP cap was free to walk around
//     without even naming an address.
//   - One address had many spellings. 1.2.3.4, ::ffff:1.2.3.4 and
//     2001:db8::1 versus 2001:0db8:0000:0000:0000:0000:0000:0001 are the same
//     destination and used to be different buckets, so a caller could dodge
//     its own budget by re-spelling its address.
//
// Anything that is not a parseable IP goes to the unattributed bucket, which
// is deliberately much smaller than the per-IP one.
func normalizeSignupClientIP(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	// Fold an IPv4-mapped IPv6 address onto its IPv4 form so the two spellings
	// share one bucket; net.IP.String already canonicalises the rest.
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// signupEmailKey / signupIPKey / signupGlobalKey build the bucket keys.
func signupEmailKey(prefix, email string) string { return prefix + ":email:" + hashForKey(email) }

func signupIPKey(prefix, ip string) string {
	if ip == "" {
		return prefix + ":ip:unattributed"
	}
	return prefix + ":ip:" + hashForKey(ip)
}

func signupGlobalKey(prefix string) string { return prefix + ":global" }

// checkSignupLimits decides the request against EVERY supplied budget before
// charging any of them, and maps the outcome to a gRPC status.
//
// The two phases are the point.
//
// A single pass that consumed as it went made a refused request spend every
// budget it reached before the one that refused it. Since the budgets are
// ordered from narrowest to widest, that meant traffic refused by a per-address
// or per-IP budget still drew down the platform-wide bucket — so a source that
// had already been told "no" could exhaust the allowance shared by everyone
// else. Peeking first means a request that is going to be refused costs
// nothing anywhere.
//
// The consume pass keeps the same narrow-to-wide order, so if a concurrent
// caller takes the last unit of a narrow budget between the two passes, the
// widest buckets are the ones that have not been charged yet.
//
// Fail-closed on a missing or broken limiter: codes.Unavailable, request
// refused. Over budget: codes.ResourceExhausted.
func (s *DaemonServer) checkSignupLimits(ctx context.Context, limits ...signupLimit) error {
	if s.signupLimiter == nil {
		return status.Error(codes.Unavailable,
			"signup is temporarily unavailable; please try again shortly")
	}
	for _, l := range limits {
		if err := s.signupLimitStatus(ctx, s.signupLimiter.Peek(ctx, l.key, l.window)); err != nil {
			return err
		}
	}
	for _, l := range limits {
		if err := s.signupLimitStatus(ctx, s.signupLimiter.Check(ctx, l.key, l.window)); err != nil {
			return err
		}
	}
	return nil
}

// signupLimitStatus maps one limiter verdict to a gRPC status.
func (s *DaemonServer) signupLimitStatus(ctx context.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ratelimit.ErrRateLimited):
		// Deliberately generic. The message does not say which bucket was hit,
		// because "you have hit the per-email limit" would confirm that this
		// address has been requested before.
		return status.Error(codes.ResourceExhausted,
			"too many signup requests; please try again later")
	default:
		s.logger.ErrorContext(ctx, "signup rate limiter unavailable; refusing request",
			"error", err.Error())
		return status.Error(codes.Unavailable,
			"signup is temporarily unavailable; please try again shortly")
	}
}

// requestVerificationLimits is the budget set for RequestEmailVerification.
//
// Ordered narrowest scope first, global last. Order is not cosmetic: it decides
// which budgets a request has already been charged for if a racing caller takes
// the last unit of a narrower one mid-flight, and the shared bucket is the one
// that must be charged last.
func requestVerificationLimits(email, clientIP string) []signupLimit {
	return []signupLimit{
		{signupEmailKey("sv", email) + ":h", signupRequestPerEmailHour},
		{signupEmailKey("sv", email) + ":d", signupRequestPerEmailDay},
		ipLimitFor("sv", clientIP, signupRequestPerIPHour),
		{signupIPKey("sv", clientIP) + ":d", signupRequestPerIPDay},
		{signupGlobalKey("sv"), signupRequestGlobalHour},
	}
}

// ipLimitFor picks the hourly IP budget, routing unattributed traffic to its
// own much smaller bucket rather than to the normal per-IP allowance.
//
// attributed is the window to charge when the caller named a well-formed
// address; it differs per RPC because the RPCs cost different amounts.
func ipLimitFor(prefix, clientIP string, attributed ratelimit.Window) signupLimit {
	if clientIP == "" {
		return signupLimit{signupIPKey(prefix, "") + ":h", signupRequestUnattributedHour}
	}
	return signupLimit{signupIPKey(prefix, clientIP) + ":h", attributed}
}

// redeemLimits / completeLimits are the budget sets for the remaining two RPCs.
//
// Each pairs a per-IP budget — shaping, since client_ip is a claim — with a
// peer-independent one that the claim cannot influence. Narrowest first, as
// everywhere else on this surface: the shared bucket is charged last.
func redeemLimits(clientIP string) []signupLimit {
	return []signupLimit{
		ipLimitFor("sr", clientIP, signupRedeemPerIPHour),
		{signupGlobalKey("sr"), signupRedeemGlobalHour},
	}
}

func completeLimits(clientIP string) []signupLimit {
	return []signupLimit{
		ipLimitFor("sc", clientIP, signupCompletePerIPHour),
		{signupGlobalKey("sc"), signupCompleteGlobalHour},
	}
}

// attachCustomerLimits is the budget set for AttachSignupCustomer.
//
// It exists because that RPC used to be the one unauthenticated signup door
// with no budget at all, while still writing to Postgres on every call. A
// session-scoped write is cheap, so the allowance is loose; the point is that
// there is one.
func attachCustomerLimits(clientIP string) []signupLimit {
	return []signupLimit{
		ipLimitFor("sa", clientIP, signupAttachPerIPHour),
		{signupGlobalKey("sa"), signupAttachGlobalHour},
	}
}
