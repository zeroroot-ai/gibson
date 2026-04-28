package idp

import "errors"

// Sentinel errors returned by AdminClient implementations.
// Callers use errors.Is to inspect them; implementations wrap these
// sentinels with additional context using fmt.Errorf("...: %w", ErrXxx).
//
// The orchestration layer (TenantAdminService handlers) maps these to
// gRPC status codes:
//
//   ErrNotFound      → codes.NotFound
//   ErrAlreadyExists → codes.AlreadyExists
//   ErrPermission    → codes.Internal (admin misconfigured — operator issue)
//   ErrUnreachable   → codes.Unavailable
//   ErrUpstream      → codes.Internal (sanitized message — hide provider details)
var (
	// ErrNotFound is returned when the requested resource does not exist in the IdP.
	ErrNotFound = errors.New("idp: not found")

	// ErrAlreadyExists is returned when attempting to create a resource that
	// already exists in the IdP (e.g., duplicate service account name).
	ErrAlreadyExists = errors.New("idp: already exists")

	// ErrUpstream is returned when the IdP returns an unexpected error response
	// (5xx, malformed response, etc.). The error should be wrapped to include
	// sanitized context for operator diagnostics.
	ErrUpstream = errors.New("idp: upstream provider error")

	// ErrPermission is returned when the admin client lacks the necessary
	// permissions in the IdP. This usually indicates a misconfiguration
	// (wrong credentials, insufficient IdP role grant) rather than a caller error.
	ErrPermission = errors.New("idp: admin client lacks permission")

	// ErrUnreachable is returned when the IdP cannot be reached due to a network
	// error, DNS failure, or timeout.
	ErrUnreachable = errors.New("idp: provider unreachable")
)
