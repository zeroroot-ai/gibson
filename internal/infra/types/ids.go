package types

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// ID is a custom type that wraps a UUID string.
// It provides type-safe UUID generation, validation, and serialization.
type ID string

// NewID generates a new UUID v4 and returns it as an ID.
// It will never return an error as uuid.New() uses crypto/rand
// which panics on system-level failures (extremely rare).
func NewID() ID {
	return ID(uuid.New().String())
}

// ParseID parses and validates a string as a UUID, returning an ID.
// It returns an error if the string is not a valid UUID v4 format.
func ParseID(s string) (ID, error) {
	if s == "" {
		return "", fmt.Errorf("ID cannot be empty")
	}

	// Parse and validate the UUID
	parsedUUID, err := uuid.Parse(s)
	if err != nil {
		return "", fmt.Errorf("invalid UUID format: %w", err)
	}

	return ID(parsedUUID.String()), nil
}

// Validate checks if the ID is a valid UUID v4.
// Returns an error if the ID is invalid or empty.
func (id ID) Validate() error {
	if id == "" {
		return fmt.Errorf("ID cannot be empty")
	}

	_, err := uuid.Parse(string(id))
	if err != nil {
		return fmt.Errorf("invalid UUID format: %w", err)
	}

	return nil
}

// String returns the string representation of the ID.
func (id ID) String() string {
	return string(id)
}

// IsZero checks if the ID is empty or zero-valued.
func (id ID) IsZero() bool {
	return id == ""
}

// MarshalJSON implements the json.Marshaler interface.
// It serializes the ID as a JSON string.
func (id ID) MarshalJSON() ([]byte, error) {
	if id.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(string(id))
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It deserializes a JSON string into an ID and validates it.
func (id *ID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("failed to unmarshal ID: %w", err)
	}

	// Allow null/empty to set zero value
	if s == "" {
		*id = ""
		return nil
	}

	// Parse and validate the UUID
	parsedID, err := ParseID(s)
	if err != nil {
		return err
	}

	*id = parsedID
	return nil
}
