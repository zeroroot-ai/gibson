// Package failopensuppress exercises the suppression mechanism of the
// failopenauthorizer guard.
//
// The point of these fixtures is that the escape hatch is NOT an escape
// hatch: a bare directive is its own diagnostic, and a compensating
// guard that is named but not actually on the permissive path is
// rejected. A guard whose suppression is unmutated is a guard with an
// unlocked back door.
package failopensuppress

import (
	"context"
	"errors"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

type server struct {
	authorizer authz.Authorizer
	tenant     string
}

// requireTenantScope is the compensating guard the valid suppression
// below names. It bounds the blast radius by establishing tenant scope.
func (s *server) requireTenantScope(ctx context.Context) error {
	if s.tenant == "" {
		return errors.New("no tenant")
	}
	return nil
}

// bareDirective carries a suppression with no qualifier at all.
//
//gibsoncheck:allow fail-open-authorizer
func (s *server) bareDirective(ctx context.Context) error { // want `bare fail-open-authorizer suppression is not permitted`
	if s.authorizer == nil {
		return nil
	}
	_, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
	return err
}

// notOnPermissivePath names a real symbol that is never called before
// the branch the suppression excuses.
//
//gibsoncheck:allow fail-open-authorizer compensating=requireTenantScope
func (s *server) notOnPermissivePath(ctx context.Context) error { // want `is named but not on the permissive path`
	if s.authorizer == nil {
		return nil
	}
	if err := s.requireTenantScope(ctx); err != nil {
		return err
	}
	_, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
	return err
}

// unresolvableGuard names a symbol that does not exist. A typo or a
// renamed guard reds the build.
//
//gibsoncheck:allow fail-open-authorizer compensating=noSuchGuard
func (s *server) unresolvableGuard(ctx context.Context) error { // want `does not resolve to a function or method in scope`
	if s.authorizer == nil {
		return nil
	}
	_, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
	return err
}

// bothQualifiers supplies compensating= and issue= together.
//
//gibsoncheck:allow fail-open-authorizer compensating=requireTenantScope issue=gibson#1 expires=2099-01-01
func (s *server) bothQualifiers(ctx context.Context) error { // want `must name exactly one of compensating= or issue=`
	if s.authorizer == nil {
		return nil
	}
	_, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
	return err
}

// issueWithoutExpiry omits the mandatory expiry date.
//
//gibsoncheck:allow fail-open-authorizer issue=gibson#1232
func (s *server) issueWithoutExpiry(ctx context.Context) error { // want `must also carry expires=`
	if s.authorizer == nil {
		return nil
	}
	_, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
	return err
}

// expiredIssue carries a date in the past. The debt marker must not
// outlive the debt.
//
//gibsoncheck:allow fail-open-authorizer issue=gibson#1232 expires=2020-01-01
func (s *server) expiredIssue(ctx context.Context) error { // want `suppression expired on 2020-01-01`
	if s.authorizer == nil {
		return nil
	}
	_, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
	return err
}

// farFutureIssue asks for a horizon beyond the cap, so renewal cannot
// be made invisible by picking a distant date.
//
//gibsoncheck:allow fail-open-authorizer issue=gibson#1232 expires=2099-01-01
func (s *server) farFutureIssue(ctx context.Context) error { // want `is more than 90 days out`
	if s.authorizer == nil {
		return nil
	}
	_, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
	return err
}

// validCompensating names a guard that IS on the permissive path — it
// runs before the nil branch is reached. This is the one legitimate
// claim this suppression can make, and it is checked.
//
//gibsoncheck:allow fail-open-authorizer compensating=requireTenantScope
func (s *server) validCompensating(ctx context.Context) error {
	if err := s.requireTenantScope(ctx); err != nil {
		return err
	}
	if s.authorizer == nil {
		return nil
	}
	_, err := s.authorizer.Check(ctx, "user:x", "admin", "tenant:t")
	return err
}
