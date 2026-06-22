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

// MissionStatus represents the execution state of a mission
type MissionStatus string

const (
	MissionStatusPending   MissionStatus = "pending"
	MissionStatusRunning   MissionStatus = "running"
	MissionStatusCompleted MissionStatus = "completed"
	MissionStatusFailed    MissionStatus = "failed"
	MissionStatusCancelled MissionStatus = "cancelled"
)

// String returns the string representation of MissionStatus
func (s MissionStatus) String() string {
	return string(s)
}

// IsValid checks if the MissionStatus is a valid value
func (s MissionStatus) IsValid() bool {
	switch s {
	case MissionStatusPending, MissionStatusRunning, MissionStatusCompleted,
		MissionStatusFailed, MissionStatusCancelled:
		return true
	default:
		return false
	}
}

// MarshalJSON implements json.Marshaler
func (s MissionStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// UnmarshalJSON implements json.Unmarshaler
func (s *MissionStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	status := MissionStatus(str)
	if !status.IsValid() {
		return fmt.Errorf("invalid mission status: %s", str)
	}

	*s = status
	return nil
}

// FindingStatus represents the state of a security finding
type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusConfirmed     FindingStatus = "confirmed"
	FindingStatusFixed         FindingStatus = "fixed"
	FindingStatusFalsePositive FindingStatus = "false_positive"
	FindingStatusWontFix       FindingStatus = "wont_fix"
)

// String returns the string representation of FindingStatus
func (s FindingStatus) String() string {
	return string(s)
}

// IsValid checks if the FindingStatus is a valid value
func (s FindingStatus) IsValid() bool {
	switch s {
	case FindingStatusOpen, FindingStatusConfirmed, FindingStatusFixed,
		FindingStatusFalsePositive, FindingStatusWontFix:
		return true
	default:
		return false
	}
}

// MarshalJSON implements json.Marshaler
func (s FindingStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// UnmarshalJSON implements json.Unmarshaler
func (s *FindingStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	status := FindingStatus(str)
	if !status.IsValid() {
		return fmt.Errorf("invalid finding status: %s", str)
	}

	*s = status
	return nil
}
