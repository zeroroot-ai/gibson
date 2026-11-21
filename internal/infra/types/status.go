// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package types

import (
	"encoding/json"
	"fmt"
)

// TargetStatus represents the operational state of a target system
type TargetStatus string

const (
	TargetStatusActive   TargetStatus = "active"
	TargetStatusInactive TargetStatus = "inactive"
	TargetStatusError    TargetStatus = "error"
)

// String returns the string representation of TargetStatus
func (s TargetStatus) String() string {
	return string(s)
}

// IsValid checks if the TargetStatus is a valid value
func (s TargetStatus) IsValid() bool {
	switch s {
	case TargetStatusActive, TargetStatusInactive, TargetStatusError:
		return true
	default:
		return false
	}
}

// MarshalJSON implements json.Marshaler
func (s TargetStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// UnmarshalJSON implements json.Unmarshaler
func (s *TargetStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	status := TargetStatus(str)
	if !status.IsValid() {
		return fmt.Errorf("invalid target status: %s", str)
	}

	*s = status
	return nil
}

// CredentialStatus represents the state of authentication credentials
type CredentialStatus string

const (
	CredentialStatusActive   CredentialStatus = "active"
	CredentialStatusInactive CredentialStatus = "inactive"
	CredentialStatusExpired  CredentialStatus = "expired"
	CredentialStatusRevoked  CredentialStatus = "revoked"
	CredentialStatusRotating CredentialStatus = "rotating"
)

// String returns the string representation of CredentialStatus
func (s CredentialStatus) String() string {
	return string(s)
}

// IsValid checks if the CredentialStatus is a valid value
func (s CredentialStatus) IsValid() bool {
	switch s {
	case CredentialStatusActive, CredentialStatusInactive, CredentialStatusExpired,
		CredentialStatusRevoked, CredentialStatusRotating:
		return true
	default:
		return false
	}
}

// MarshalJSON implements json.Marshaler
func (s CredentialStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// UnmarshalJSON implements json.Unmarshaler
func (s *CredentialStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	status := CredentialStatus(str)
	if !status.IsValid() {
		return fmt.Errorf("invalid credential status: %s", str)
	}

	*s = status
	return nil
}
