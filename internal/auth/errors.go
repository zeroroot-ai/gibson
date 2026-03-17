package auth

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthError represents an authentication or authorization error.
//
// Implements error interface and includes gRPC status code
// for proper error reporting in gRPC interceptors.
type AuthError struct {
	// Code is the gRPC status code for this error.
	Code codes.Code

	// Message is the human-readable error message.
	Message string

	// Reason provides additional context about the failure.
	// Examples: "token_expired", "invalid_signature", "unknown_issuer"
	Reason string

	// Err is the underlying error that caused this auth error.
	// Optional - may be nil for top-level errors.
	Err error
}

// Error implements the error interface.
func (e *AuthError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("%s: %s", e.Reason, e.Message)
	}
	return e.Message
}

// Unwrap implements error unwrapping for errors.Is and errors.As.
func (e *AuthError) Unwrap() error {
	return e.Err
}

// GRPCStatus converts the AuthError to a gRPC status.
//
// This allows the error to be returned directly from gRPC handlers
// and automatically converted to the correct status code.
func (e *AuthError) GRPCStatus() *status.Status {
	return status.New(e.Code, e.Error())
}

// Common authentication errors with appropriate gRPC status codes.

// ErrMissingToken is returned when no bearer token is provided.
func ErrMissingToken() error {
	return &AuthError{
		Code:    codes.Unauthenticated,
		Message: "missing bearer token in authorization header",
		Reason:  "missing_token",
	}
}

// ErrTokenExpired is returned when a token has expired.
func ErrTokenExpired() error {
	return &AuthError{
		Code:    codes.Unauthenticated,
		Message: "token has expired",
		Reason:  "token_expired",
	}
}

// ErrInvalidSignature is returned when token signature validation fails.
func ErrInvalidSignature() error {
	return &AuthError{
		Code:    codes.Unauthenticated,
		Message: "invalid token signature",
		Reason:  "invalid_signature",
	}
}

// ErrUnknownIssuer is returned when the token issuer is not configured.
func ErrUnknownIssuer(issuer string) error {
	return &AuthError{
		Code:    codes.Unauthenticated,
		Message: fmt.Sprintf("unknown token issuer: %s", issuer),
		Reason:  "unknown_issuer",
	}
}

// ErrInvalidAudience is returned when the token audience doesn't match configuration.
func ErrInvalidAudience(expected, actual string) error {
	return &AuthError{
		Code:    codes.Unauthenticated,
		Message: fmt.Sprintf("invalid token audience: expected %s, got %s", expected, actual),
		Reason:  "invalid_audience",
	}
}

// ErrMalformedToken is returned when the token cannot be parsed.
func ErrMalformedToken(err error) error {
	return &AuthError{
		Code:    codes.Unauthenticated,
		Message: "malformed token",
		Reason:  "malformed_token",
		Err:     err,
	}
}

// ErrPermissionDenied is returned when an authenticated identity lacks required permissions.
func ErrPermissionDenied(action, resource string) error {
	return &AuthError{
		Code:    codes.PermissionDenied,
		Message: fmt.Sprintf("insufficient permissions for %s on %s", action, resource),
		Reason:  "permission_denied",
	}
}

// ErrNoRoleBindings is returned when no role bindings match the identity's claims.
func ErrNoRoleBindings() error {
	return &AuthError{
		Code:    codes.PermissionDenied,
		Message: "no role bindings match identity claims",
		Reason:  "no_role_bindings",
	}
}

// ErrJWKSFetchFailed is returned when fetching JWKS from an issuer fails.
func ErrJWKSFetchFailed(issuer string, err error) error {
	return &AuthError{
		Code:    codes.Unavailable,
		Message: fmt.Sprintf("failed to fetch JWKS from %s", issuer),
		Reason:  "jwks_fetch_failed",
		Err:     err,
	}
}

// ErrAuthDisabled is returned when attempting auth operations with auth disabled.
//
// This is NOT a gRPC error - it's an internal error that should be caught
// before reaching the gRPC layer.
func ErrAuthDisabled() error {
	return &AuthError{
		Code:    codes.Internal,
		Message: "authentication is disabled",
		Reason:  "auth_disabled",
	}
}

// ErrK8sAPIError is returned when Kubernetes TokenReview API call fails.
func ErrK8sAPIError(err error) error {
	return &AuthError{
		Code:    codes.Unavailable,
		Message: "kubernetes tokenreview api error",
		Reason:  "k8s_api_error",
		Err:     err,
	}
}

// ErrInvalidToken is returned when a token is structurally invalid.
func ErrInvalidToken(err error) error {
	return &AuthError{
		Code:    codes.Unauthenticated,
		Message: "invalid token",
		Reason:  "invalid_token",
		Err:     err,
	}
}

// Sentinel errors for use in interceptor.
var (
	errMissingToken = &AuthError{
		Code:    codes.Unauthenticated,
		Message: "missing bearer token in authorization header",
		Reason:  "missing_token",
	}
	errInvalidToken = &AuthError{
		Code:    codes.Unauthenticated,
		Message: "invalid token format",
		Reason:  "invalid_token",
	}
)

// Error checking functions for use in interceptors.

// IsMissingTokenError checks if an error is a missing token error.
func IsMissingTokenError(err error) bool {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Reason == "missing_token"
	}
	return false
}

// IsInvalidTokenError checks if an error is an invalid token error.
func IsInvalidTokenError(err error) bool {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Reason == "invalid_token" || authErr.Reason == "malformed_token"
	}
	return false
}

// IsTokenExpiredError checks if an error is a token expired error.
func IsTokenExpiredError(err error) bool {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Reason == "token_expired"
	}
	return false
}

// IsInvalidSignatureError checks if an error is an invalid signature error.
func IsInvalidSignatureError(err error) bool {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Reason == "invalid_signature"
	}
	return false
}

// IsUnknownIssuerError checks if an error is an unknown issuer error.
func IsUnknownIssuerError(err error) bool {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Reason == "unknown_issuer"
	}
	return false
}

// IsAudienceMismatchError checks if an error is an audience mismatch error.
func IsAudienceMismatchError(err error) bool {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Reason == "invalid_audience"
	}
	return false
}

// IsPermissionDeniedError checks if an error is a permission denied error.
func IsPermissionDeniedError(err error) bool {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Code == codes.PermissionDenied
	}
	return false
}

// Time helper functions for interceptor.

// timeNow returns the current time.
// Extracted as a function to allow mocking in tests.
var timeNow = func() time.Time {
	return time.Now()
}

// timeNever returns a time far in the future to indicate "never expires".
var timeNever = func() time.Time {
	return time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
}
