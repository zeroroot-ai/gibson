// Package failopen exercises the failopenauthorizer guard.
//
// The NEGATIVE cases are as load-bearing as the positive ones: they are
// the near-misses that a naive version of this rule reports as defects.
// If a future edit widens the rule "to catch more", these fixtures red
// the analyzer's own test instead of the repository.
package failopen

import (
	"context"
	"errors"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

type response struct {
	TenantId string
	Role     string
	IsAdmin  bool
}

type members struct {
	Memberships []string
}

type retryPolicy struct{ Attempts int }

type node struct{ RetryPolicy *retryPolicy }

type server struct {
	authorizer authz.Authorizer
	// budgetEnforcer is a non-authz optional dependency; nil-guarding
	// it is not this guard's business.
	budgetEnforcer any
	node           *node
}

// ---------------------------------------------------------------------------
// FO-1 positives
// ---------------------------------------------------------------------------

// requireTenantAdmin degrades to a nil error, which callers read as
// "allowed".
func (s *server) requireTenantAdmin(ctx context.Context, tenant string) error {
	if s.authorizer == nil { // want `fail-open authorization`
		return nil
	}
	ok, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:"+tenant)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("denied")
	}
	return nil
}

// canDoThing returns the bool verdict itself, so `true` is the
// permissive polarity.
func (s *server) canDoThing(ctx context.Context) (bool, error) {
	if s.authorizer == nil { // want `fail-open authorization`
		return true, nil
	}
	return s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
}

// getMyPermissions synthesises an authority-bearing response for a
// caller whose permissions were never checked.
func (s *server) getMyPermissions(ctx context.Context) (*response, error) {
	if s.authorizer == nil { // want `fail-open authorization`
		return &response{TenantId: "t", Role: "member"}, nil
	}
	if _, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t"); err != nil {
		return nil, err
	}
	return &response{TenantId: "t", Role: "admin", IsAdmin: true}, nil
}

// ---------------------------------------------------------------------------
// FO-2 positive — the omission form
// ---------------------------------------------------------------------------

// resolveSubject performs its only authorization check inside the
// `!= nil` branch, so a nil dependency skips the check entirely.
func (s *server) resolveSubject(ctx context.Context, impersonate string) (string, error) {
	if impersonate != "" {
		if s.authorizer != nil { // want `fail-open authorization`
			isAdmin, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
			if err != nil || !isAdmin {
				return "", errors.New("impersonation requires tenant admin")
			}
		}
		return impersonate, nil
	}
	return "self", nil
}

// ---------------------------------------------------------------------------
// NEGATIVES — every one of these is a near-miss a naive rule reports
// ---------------------------------------------------------------------------

// canRevokeSessions DENIES on a nil dependency. Same `== nil` token,
// opposite polarity. This is the fixture that proves the rule is about
// semantics rather than syntax.
func (s *server) canRevokeSessions(ctx context.Context) (bool, error) {
	if s.authorizer == nil {
		return false, nil
	}
	return s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
}

// requireAdminFailClosed returns a real error, the corrected shape.
func (s *server) requireAdminFailClosed(ctx context.Context) error {
	if s.authorizer == nil {
		return errors.New("authorizer not configured")
	}
	if _, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t"); err != nil {
		return err
	}
	return nil
}

// listMembers returns an EMPTY response. An empty response leaks
// nothing, so it is not an authority assertion.
func (s *server) listMembers(ctx context.Context) (*members, error) {
	if s.authorizer == nil {
		return &members{}, nil
	}
	users, err := s.authorizer.ListUsers(ctx, "tenant", "tenant:t", "member")
	if err != nil {
		return nil, err
	}
	return &members{Memberships: users}, nil
}

// wireUp holds a reference but never decides — Gate 1 excludes it. This
// is the readiness-probe and wiring shape.
func (s *server) wireUp() []func() error {
	var out []func() error
	if s.authorizer != nil {
		out = append(out, func() error { return errors.New("not ready") })
	}
	return out
}

// retryGuard is a plain value nil-guard on a non-security type. The
// TYPE gate is what keeps this out; a keyword rule reports it.
func (s *server) retryGuard() error {
	if s.node.RetryPolicy != nil {
		if s.node.RetryPolicy.Attempts == 0 {
			return errors.New("bad policy")
		}
	}
	return nil
}

// budgetGuard nil-guards a non-authz optional dependency.
func (s *server) budgetGuard(ctx context.Context) error {
	if s.budgetEnforcer == nil {
		return nil
	}
	_, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
	return err
}
