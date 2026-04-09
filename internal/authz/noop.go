package authz

import (
	"context"
	"log/slog"
)

// noopAuthorizer is a no-op implementation of the Authorizer interface.
//
// It is used when authz.enabled is false in config, or when FGA is unreachable
// in dev mode with require_ready: false. All Check calls return (true, nil) so
// that existing behavior is preserved unchanged. Write and Delete calls log a
// WARN so that dev-mode usage is visible in logs without failing operations.
//
// This design allows the rest of the codebase to call Authorizer.Check
// unconditionally without nil-checking — startup wires either the real or
// no-op implementation into the daemon.
//
// noopAuthorizer is safe for concurrent use.
type noopAuthorizer struct {
	logger *slog.Logger
}

// NewNoopAuthorizer creates a no-op Authorizer that allows all checks.
//
// The logger is used to emit WARN messages on mutating calls (Write, Delete)
// so that operators can tell the authorizer is in no-op mode.
func NewNoopAuthorizer(logger *slog.Logger) Authorizer {
	if logger == nil {
		logger = slog.Default()
	}
	return &noopAuthorizer{logger: logger}
}

// Check always returns (true, nil) — the no-op authorizer permits everything.
func (n *noopAuthorizer) Check(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}

// BatchCheck returns a slice of true values — all checks pass in no-op mode.
func (n *noopAuthorizer) BatchCheck(_ context.Context, checks []CheckRequest) ([]bool, error) {
	results := make([]bool, len(checks))
	for i := range results {
		results[i] = true
	}
	return results, nil
}

// Write logs a WARN and returns nil — mutations are ignored in no-op mode.
//
// The WARN helps operators notice that authorization tuples are being written
// but not actually persisted, which may indicate a misconfiguration.
func (n *noopAuthorizer) Write(_ context.Context, tuples []Tuple) error {
	n.logger.Warn("authz: Write called on no-op authorizer — tuple not persisted",
		"tuple_count", len(tuples),
		"mode", "noop",
	)
	return nil
}

// Delete logs a WARN and returns nil — mutations are ignored in no-op mode.
func (n *noopAuthorizer) Delete(_ context.Context, tuples []Tuple) error {
	n.logger.Warn("authz: Delete called on no-op authorizer — tuple not removed",
		"tuple_count", len(tuples),
		"mode", "noop",
	)
	return nil
}

// ListObjects returns an empty slice — no objects are known in no-op mode.
func (n *noopAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return []string{}, nil
}

// ListUsers returns an empty slice — no users are known in no-op mode.
func (n *noopAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return []string{}, nil
}

// StoreID returns an empty string — the no-op authorizer has no backing store.
func (n *noopAuthorizer) StoreID() string {
	return ""
}

// ModelID returns an empty string — the no-op authorizer has no authorization model.
func (n *noopAuthorizer) ModelID() string {
	return ""
}

// Close is a no-op — there is no connection to release.
func (n *noopAuthorizer) Close() error {
	return nil
}
