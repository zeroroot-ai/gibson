// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// signup_rate_limit_test.go — the chokepoint's own behaviour: which budgets a
// request draws on, and what happens when the limiter cannot answer.

import (
	"context"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/ratelimit"
)

// TestRefusedTrafficCannotDrainTheSharedBudget is the end-to-end regression
// test for the abuse control, run against the real limiter and the real budget
// list rather than a stub.
//
// One source, one address, sustained traffic. The per-address budget (3/hour)
// refuses almost all of it. The question is what those refusals cost: under the
// old shape they each spent a unit of the platform-wide bucket on the way past,
// so a single refused source could exhaust the allowance shared by every other
// prospective customer and hold signup closed for all of them.
//
// The last assertion is the one that matters: after the burst, an unrelated
// person on an unrelated address is still able to sign up.
func TestRefusedTrafficCannotDrainTheSharedBudget(t *testing.T) {
	mr := miniredis.RunT(t)
	s := &DaemonServer{logger: testSlogLogger}
	s.signupLimiter = ratelimit.NewWindowLimiter(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	ctx := context.Background()

	const attackerIP = "198.51.100.4"
	const attackerEmail = "attacker@example.com"

	admitted, refused := 0, 0
	// Comfortably more than signupRequestGlobalHour.Max, so the old behaviour
	// would have emptied the shared bucket several times over.
	for i := range 400 {
		if err := s.checkSignupLimits(ctx, requestVerificationLimits(attackerEmail, attackerIP)...); err != nil {
			if status.Code(err) != codes.ResourceExhausted {
				t.Fatalf("unexpected status on request %d: %v", i, err)
			}
			refused++
			continue
		}
		admitted++
	}

	// The narrow budget is what bounds this source, and it is small.
	if admitted != signupRequestPerEmailHour.Max {
		t.Errorf("admitted %d requests for one address, want %d (the per-address hourly budget)",
			admitted, signupRequestPerEmailHour.Max)
	}
	if refused == 0 {
		t.Fatal("nothing was refused; the burst did not exercise the limiter")
	}

	// The shared bucket should have been charged only for the handful of
	// requests that were actually admitted.
	if err := s.signupLimiter.Peek(ctx, signupGlobalKey("sv"), signupRequestGlobalHour); err != nil {
		t.Errorf("the shared global budget is exhausted after %d refused requests: %v", refused, err)
	}

	// The property that the whole control exists for.
	if err := s.checkSignupLimits(ctx, requestVerificationLimits("someone-else@example.com", "203.0.113.9")...); err != nil {
		t.Errorf("an unrelated signup was locked out by refused traffic from another source: %v", err)
	}
}

// TestRefusedTrafficCannotPinAnAddressOutOfSignup — the same defect aimed at a
// victim rather than at the platform. Sustained requests for someone else's
// address must not keep that address's window permanently full.
func TestRefusedTrafficCannotPinAnAddressOutOfSignup(t *testing.T) {
	mr := miniredis.RunT(t)
	s := &DaemonServer{logger: testSlogLogger}
	s.signupLimiter = ratelimit.NewWindowLimiter(redis.NewClient(&redis.Options{Addr: mr.Addr()}))
	ctx := context.Background()

	const victim = "victim@example.com"
	victimKey := signupEmailKey("sv", victim) + ":h"

	// Spend the victim's hourly budget, then keep hammering it.
	for range 200 {
		_ = s.checkSignupLimits(ctx, requestVerificationLimits(victim, "198.51.100.4")...)
	}

	// Only the admitted requests are recorded, so the sorted set holds exactly
	// the budget — not one member per attempt.
	members, err := mr.ZMembers("ratelimit:window:" + victimKey)
	if err != nil {
		t.Fatalf("reading the victim's window: %v", err)
	}
	if len(members) != signupRequestPerEmailHour.Max {
		t.Errorf("the victim's window holds %d events after 200 attempts, want %d; refused attempts are being recorded",
			len(members), signupRequestPerEmailHour.Max)
	}
}

// recordingLimiter captures the keys and windows each call draws on, keeping
// peeks (which cost nothing) separate from checks (which spend budget).
type recordingLimiter struct {
	peeked  []string
	keys    []string
	windows []ratelimit.Window
	err     error
}

func (r *recordingLimiter) Peek(_ context.Context, key string, _ ratelimit.Window) error {
	r.peeked = append(r.peeked, key)
	return r.err
}

func (r *recordingLimiter) Check(_ context.Context, key string, w ratelimit.Window) error {
	r.keys = append(r.keys, key)
	r.windows = append(r.windows, w)
	return r.err
}

// TestCheckSignupLimits_FailsClosed is the property that matters most: a
// limiter that is missing or broken refuses the request. On an unauthenticated
// surface, "cannot count" must not degrade into "no limits".
func TestCheckSignupLimits_FailsClosed(t *testing.T) {
	t.Run("no limiter wired", func(t *testing.T) {
		s := &DaemonServer{logger: testSlogLogger}
		err := s.checkSignupLimits(context.Background(), signupLimit{"sv:global", signupRequestGlobalHour})
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("status = %v, want Unavailable", err)
		}
	})

	t.Run("limiter unreachable", func(t *testing.T) {
		s := &DaemonServer{logger: testSlogLogger}
		s.signupLimiter = &recordingLimiter{err: ratelimit.ErrLimiterUnavailable}
		err := s.checkSignupLimits(context.Background(), signupLimit{"sv:global", signupRequestGlobalHour})
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("status = %v, want Unavailable", err)
		}
	})

	t.Run("over budget", func(t *testing.T) {
		s := &DaemonServer{logger: testSlogLogger}
		s.signupLimiter = &recordingLimiter{err: ratelimit.ErrRateLimited}
		err := s.checkSignupLimits(context.Background(), signupLimit{"sv:global", signupRequestGlobalHour})
		if status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("status = %v, want ResourceExhausted", err)
		}
		// The message must not name the bucket that tripped. "Per-email limit
		// reached" would confirm that this address has been requested before.
		msg := status.Convert(err).Message()
		for _, leak := range []string{"email", "global", "ip"} {
			if strings.Contains(strings.ToLower(msg), leak) {
				t.Errorf("the rate-limit message names the bucket that tripped: %q", msg)
			}
		}
	})
}

// TestRequestVerificationLimits_CoversEveryDimension pins the budget set for
// the entry point: a global breaker, per-address hour and day budgets, and
// per-IP hour and day budgets. Dropping any one of them leaves an unmetered
// axis on an unauthenticated mail sender.
func TestRequestVerificationLimits_CoversEveryDimension(t *testing.T) {
	limits := requestVerificationLimits("owner@example.com", "203.0.113.7")
	if len(limits) != 5 {
		t.Fatalf("limits = %d, want 5 (global + email hour/day + ip hour/day)", len(limits))
	}

	var globals, emails, ips int
	for _, l := range limits {
		switch {
		case strings.HasSuffix(l.key, ":global"):
			globals++
		case strings.Contains(l.key, ":email:"):
			emails++
		case strings.Contains(l.key, ":ip:"):
			ips++
		default:
			t.Errorf("unclassified budget key %q", l.key)
		}
		if l.window.Max <= 0 || l.window.Period <= 0 {
			t.Errorf("key %q has an empty budget: %+v", l.key, l.window)
		}
	}
	if globals != 1 || emails != 2 || ips != 2 {
		t.Errorf("budget mix = global:%d email:%d ip:%d, want 1/2/2", globals, emails, ips)
	}
}

// TestSignupLimitKeys_DoNotCarryPlaintextIdentifiers — these keys live in a
// cache operators routinely dump, and the rows they describe belong to people
// who have not yet consented to anything.
func TestSignupLimitKeys_DoNotCarryPlaintextIdentifiers(t *testing.T) {
	for _, l := range requestVerificationLimits("owner@example.com", "203.0.113.7") {
		if strings.Contains(l.key, "owner@example.com") {
			t.Errorf("key %q carries the plaintext address", l.key)
		}
		if strings.Contains(l.key, "203.0.113.7") {
			t.Errorf("key %q carries the plaintext IP", l.key)
		}
	}
}

// TestUnattributedTrafficGetsItsOwnBucket proves a request the edge could not
// attribute does NOT fall into the normal per-IP allowance under an "unknown"
// key.
//
// The distinction is per-source versus shared. An attributed request draws on a
// budget that only its own IP can spend, so a hundred honest sources get a
// hundred separate allowances. Unattributed requests all share ONE small
// budget, because they are indistinguishable from each other — nothing about
// them can be metered separately. Folding them into the per-IP scheme under a
// literal "unknown" key would give that single anonymous cohort the same
// allowance a single identified source gets, which is the wrong shape in both
// directions.
func TestUnattributedTrafficGetsItsOwnBucket(t *testing.T) {
	attributed := ipLimitFor("sv", "203.0.113.7", signupRequestPerIPHour)
	other := ipLimitFor("sv", "198.51.100.4", signupRequestPerIPHour)
	unattributed := ipLimitFor("sv", "", signupRequestPerIPHour)

	if attributed.key == unattributed.key {
		t.Fatalf("attributed and unattributed traffic share a key: %q", attributed.key)
	}
	if attributed.key == other.key {
		t.Errorf("two different source IPs share a budget: %q", attributed.key)
	}
	if !strings.Contains(unattributed.key, "unattributed") {
		t.Errorf("unattributed key = %q, want an explicit shared bucket", unattributed.key)
	}
	// Every unattributed request lands in the SAME bucket, whatever else about
	// it varies — that is what makes it a global cap rather than a per-source
	// allowance an attacker can multiply.
	if ipLimitFor("sv", "", signupRequestPerIPHour).key != unattributed.key {
		t.Errorf("the unattributed bucket is not stable")
	}
	if unattributed.window != signupRequestUnattributedHour {
		t.Errorf("unattributed budget = %+v, want the dedicated unattributed window %+v",
			unattributed.window, signupRequestUnattributedHour)
	}
	// It is also an absolute cap on the whole cohort, so it must stay small.
	if unattributed.window.Max > 50 {
		t.Errorf("the shared unattributed budget (%d/hour) is too large to be a meaningful cap",
			unattributed.window.Max)
	}
}

// TestSignupLimits_ARefusedRequestSpendsNothing — a request that is turned away
// must not have charged ANY budget, not merely the ones after the refusal.
//
// The old shape consumed as it walked the list, so a request refused by a
// narrow budget had already spent every wider one it passed on the way —
// including the platform-wide bucket. That let a source which had already been
// told "no" drain the allowance everyone else shares.
func TestSignupLimits_ARefusedRequestSpendsNothing(t *testing.T) {
	rec := &recordingLimiter{err: ratelimit.ErrRateLimited}
	s := &DaemonServer{logger: testSlogLogger}
	s.signupLimiter = rec

	_ = s.checkSignupLimits(context.Background(), requestVerificationLimits("a@b.c", "203.0.113.7")...)
	if len(rec.keys) != 0 {
		t.Errorf("a refused request consumed %d budgets (%v), want 0", len(rec.keys), rec.keys)
	}
	if len(rec.peeked) != 1 {
		t.Errorf("peeked %d budgets after the first refusal, want 1 (short-circuit)", len(rec.peeked))
	}
}

// peekOKCheckDeniesLimiter admits every Peek but denies every Check, modeling
// a budget a concurrent caller spends between the two passes.
type peekOKCheckDeniesLimiter struct{}

func (peekOKCheckDeniesLimiter) Peek(_ context.Context, _ string, _ ratelimit.Window) error {
	return nil
}

func (peekOKCheckDeniesLimiter) Check(_ context.Context, _ string, _ ratelimit.Window) error {
	return ratelimit.ErrRateLimited
}

// TestCheckSignupLimits_ChecksCatchARaceAfterPeekSucceeds proves the second
// pass is not a formality: a budget a concurrent caller spends between Peek
// and Check must still refuse the request, not admit it on the strength of a
// Peek that is already stale.
func TestCheckSignupLimits_ChecksCatchARaceAfterPeekSucceeds(t *testing.T) {
	s := &DaemonServer{logger: testSlogLogger}
	s.signupLimiter = peekOKCheckDeniesLimiter{}
	err := s.checkSignupLimits(context.Background(), signupLimit{"sv:global", signupRequestGlobalHour})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("status = %v, want ResourceExhausted", err)
	}
}

// TestCompleteLimits_UnattributedTrafficGetsItsOwnBucket and
// TestAttachCustomerLimits_UnattributedTrafficGetsItsOwnBucket pin the
// clientIP=="" branch of each budget-set builder — the same shared-bucket
// shape TestUnattributedTrafficGetsItsOwnBucket already proves for
// ipLimitFor, applied to the two builders that inline the same check.
func TestCompleteLimits_UnattributedTrafficGetsItsOwnBucket(t *testing.T) {
	limits := completeLimits("")
	if len(limits) != 2 {
		t.Fatalf("completeLimits(\"\") = %d limits, want the IP bucket plus the peer-independent one", len(limits))
	}
	if limits[0].window != signupRequestUnattributedHour {
		t.Errorf("completeLimits(\"\") window = %+v, want the shared unattributed budget", limits[0].window)
	}
	if attributed := completeLimits("203.0.113.7"); attributed[0].key == limits[0].key {
		t.Errorf("attributed and unattributed traffic share a completion budget: %q", limits[0].key)
	}
}

func TestAttachCustomerLimits_UnattributedTrafficGetsItsOwnBucket(t *testing.T) {
	limits := attachCustomerLimits("")
	if len(limits) != 2 {
		t.Fatalf("attachCustomerLimits(\"\") = %d limits, want the IP bucket plus the peer-independent one", len(limits))
	}
	if limits[0].window != signupRequestUnattributedHour {
		t.Errorf("attachCustomerLimits(\"\") window = %+v, want the shared unattributed budget", limits[0].window)
	}
	if attributed := attachCustomerLimits("203.0.113.7"); attributed[0].key == limits[0].key {
		t.Errorf("attributed and unattributed traffic share an attach budget: %q", limits[0].key)
	}
}

// TestSignupLimits_AnAdmittedRequestSpendsEveryBudget — the counterpart: when
// nothing refuses, every budget in the set is charged exactly once, and the
// shared global bucket is charged LAST so a mid-flight refusal by a narrower
// budget cannot have spent it.
func TestSignupLimits_AnAdmittedRequestSpendsEveryBudget(t *testing.T) {
	rec := &recordingLimiter{}
	s := &DaemonServer{logger: testSlogLogger}
	s.signupLimiter = rec

	limits := requestVerificationLimits("a@b.c", "203.0.113.7")
	if err := s.checkSignupLimits(context.Background(), limits...); err != nil {
		t.Fatalf("checkSignupLimits: %v", err)
	}
	if len(rec.keys) != len(limits) {
		t.Errorf("consumed %d budgets, want %d", len(rec.keys), len(limits))
	}
	if !strings.HasSuffix(rec.keys[len(rec.keys)-1], ":global") {
		t.Errorf("last budget consumed = %q, want the shared global bucket", rec.keys[len(rec.keys)-1])
	}
}
