// Package constverdict exercises the constantverdictdouble guard.
//
// The two denyAll fixtures are the ones that matter: they discard every
// decision argument, exactly like the positives, and differ ONLY in
// their verdict polarity. They prove the asymmetry is implemented — a
// double that always denies cannot hide a vulnerability, so reporting
// it would drown the operator and FGA packages in findings and the
// guard would be muted within a quarter.
package constverdict

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

func listUsersOfTypeKey(objectType, object, relation, subjectType string) string {
	return objectType + "|" + object + "|" + relation + "|" + subjectType
}

// ---------------------------------------------------------------------------
// POSITIVES
// ---------------------------------------------------------------------------

// stubAuthorizer keys on `object` alone and discards objectType,
// relation and subjectType — the shape that lets a subject-type
// mismatch pass a green test.
type stubAuthorizer struct {
	listUsersByObject map[string][]string
}

func (s *stubAuthorizer) Check(ctx context.Context, user, relation, object string) (bool, error) { // want `constant-verdict double`
	return true, nil
}

func (s *stubAuthorizer) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}

func (s *stubAuthorizer) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	return nil, nil
}

// Keys on `object` alone, discarding objectType and relation.
func (s *stubAuthorizer) ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error) { // want `constant-verdict double`
	return s.listUsersByObject[object], nil
}

func (s *stubAuthorizer) ListUsersOfType(_ context.Context, _, object, _, _ string) ([]string, error) { // want `constant-verdict double`
	return s.listUsersByObject[object], nil
}

// allowAll has UNNAMED parameters and answers true. A rule that only
// looked for `_` would miss this shape entirely.
type allowAll struct{}

func (a *allowAll) Check(context.Context, string, string, string) (bool, error) { // want `constant-verdict double`
	return true, nil
}

func (a *allowAll) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}

func (a *allowAll) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	return nil, nil
}

func (a *allowAll) ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error) {
	return nil, nil
}

func (a *allowAll) ListUsersOfType(ctx context.Context, objectType, object, relation, subjectType string) ([]string, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// NEGATIVES
// ---------------------------------------------------------------------------

// fixedAuthorizer reads all four decision arguments — the shipped fix.
type fixedAuthorizer struct {
	byKey map[string][]string
}

func (f *fixedAuthorizer) Check(ctx context.Context, user, relation, object string) (bool, error) {
	return f.byKey[user+relation+object] != nil, nil
}

func (f *fixedAuthorizer) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, 0, len(checks))
	for _, c := range checks {
		out = append(out, f.byKey[c.User+c.Relation+c.Object] != nil)
	}
	return out, nil
}

func (f *fixedAuthorizer) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	return f.byKey[user+relation+objectType], nil
}

func (f *fixedAuthorizer) ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error) {
	return f.byKey[objectType+object+relation], nil
}

func (f *fixedAuthorizer) ListUsersOfType(ctx context.Context, objectType, object, relation, subjectType string) ([]string, error) {
	return f.byKey[listUsersOfTypeKey(objectType, object, relation, subjectType)], nil
}

// denyAll discards every decision argument but DENIES. Same discard,
// opposite polarity — must stay silent.
type denyAll struct{}

func (d *denyAll) Check(_ context.Context, _, _, _ string) (bool, error) { return false, nil }

func (d *denyAll) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}

func (d *denyAll) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	return nil, nil
}

func (d *denyAll) ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error) {
	return nil, nil
}

func (d *denyAll) ListUsersOfType(ctx context.Context, objectType, object, relation, subjectType string) ([]string, error) {
	return nil, nil
}

// denyAllUnnamed pairs UNNAMED parameters with a constant DENY. This is
// the fixture that pins the asymmetry against the allowAll positive
// above: identical parameter shape, opposite verdict, opposite outcome.
type denyAllUnnamed struct{}

func (d *denyAllUnnamed) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (d *denyAllUnnamed) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}

func (d *denyAllUnnamed) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	return nil, nil
}

func (d *denyAllUnnamed) ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error) {
	return nil, nil
}

func (d *denyAllUnnamed) ListUsersOfType(ctx context.Context, objectType, object, relation, subjectType string) ([]string, error) {
	return nil, nil
}

// notAnAuthorizer has a Check method but does not satisfy the decision
// contract, so the TYPE gate excludes it.
type notAnAuthorizer struct{}

func (n *notAnAuthorizer) Check(ctx context.Context, a, b, c string) (bool, error) {
	return true, nil
}
