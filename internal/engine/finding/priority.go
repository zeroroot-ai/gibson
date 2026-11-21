// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"errors"
	"fmt"
)

// Priority is the rank of a finding, from P1 (first) to P4 (last). The
// cve-triage agent sets it. A finding ranks by its priority first and by the
// belief of its target second (gibson#1522).
type Priority string

// The four priorities. P1 is fixed first.
const (
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
	PriorityP3 Priority = "P3"
	PriorityP4 Priority = "P4"
)

// ErrInvalidPriority is the error of a priority outside P1 to P4.
var ErrInvalidPriority = errors.New("finding priority is not P1, P2, P3 or P4")

// IsValid reports whether p is one of P1 to P4. The empty priority is not
// valid. It means that no triage pass has decided.
func (p Priority) IsValid() bool { return p.Rank() > 0 }

// Rank is 1 for P1 up to 4 for P4. It is 0 for any other value.
func (p Priority) Rank() int {
	switch p {
	case PriorityP1:
		return 1
	case PriorityP2:
		return 2
	case PriorityP3:
		return 3
	case PriorityP4:
		return 4
	default:
		return 0
	}
}

// Validate returns nil for the empty priority and for P1 to P4. Any other
// value returns ErrInvalidPriority.
func (p Priority) Validate() error {
	if p == "" || p.IsValid() {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrInvalidPriority, string(p))
}
