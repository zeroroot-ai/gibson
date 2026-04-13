// Package provisioner — errors.go
//
// Shared sentinel error values and validation helpers for the provisioner package.
// These are returned by InviteHandler, TeamHandler, and related code so that gRPC
// handlers can map them to the appropriate status codes.
package provisioner

import (
	"errors"
	"regexp"
)

var (
	// ErrInvalidSignupInput is returned when a request fails validation.
	// The gRPC handler maps this to codes.InvalidArgument.
	ErrInvalidSignupInput = errors.New("invalid signup input")

	// ErrEmailAlreadyExists is returned when the email is already registered.
	// The gRPC handler maps this to codes.AlreadyExists.
	ErrEmailAlreadyExists = errors.New("email already exists")

	// ErrSignupFailed is returned when any non-validation, non-conflict step
	// in the signup pipeline fails.  The gRPC handler maps this to codes.Internal.
	ErrSignupFailed = errors.New("signup failed")
)

// emailRE is a permissive RFC-5322-inspired regex for email validation used
// across InviteHandler and other provisioner sub-packages.
var emailRE = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
