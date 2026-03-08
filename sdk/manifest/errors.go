package manifest

import "errors"

// Common manifest validation errors.
var (
	// ErrNameRequired indicates the manifest name field is required.
	ErrNameRequired = errors.New("manifest name is required")

	// ErrVersionRequired indicates the manifest version field is required.
	ErrVersionRequired = errors.New("manifest version is required")

	// ErrInvalidCapability indicates an invalid capability string format.
	ErrInvalidCapability = errors.New("invalid capability format")
)
