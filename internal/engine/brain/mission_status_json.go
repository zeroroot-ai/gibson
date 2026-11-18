// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"encoding/json"
	"fmt"
)

// UnmarshalJSON reads a stored mission state. It is the one place that knows
// the names that the mission states had before they became A2A Task states
// (ADR-0175). A stored Timeline event or snapshot that holds "pending" folds to
// MissionSubmitted. One that holds "running" folds to MissionWorking. Each
// other value passes through unchanged. Nothing else in the code reads an old
// name.
func (s *MissionStatus) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return fmt.Errorf("brain: decode mission status: %w", err)
	}
	switch name {
	case "pending":
		*s = MissionSubmitted
	case "running":
		*s = MissionWorking
	default:
		*s = MissionStatus(name)
	}
	return nil
}
