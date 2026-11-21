// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// CheckKind names the kind of the check that raised a finding (ADR-0178).
type CheckKind string

const (
	// CheckPredicate is an attack predicate of a pack. It is the strongest check.
	CheckPredicate CheckKind = "predicate"
	// CheckScan is a scan, or a mission run that looks at a target again. It is
	// the second strongest check.
	CheckScan CheckKind = "scan"
	// CheckTool is a read of a tool of the buyer. It is the weakest check.
	CheckTool CheckKind = "tool"
)

// ErrNoCheck is the error of a finding that has no valid check. The store
// refuses such a finding.
var ErrNoCheck = errors.New("finding has no valid check")

// IsValid reports whether k is one of the three kinds.
func (k CheckKind) IsValid() bool { return k.strength() > 0 }

func (k CheckKind) strength() int {
	switch k {
	case CheckPredicate:
		return 3
	case CheckScan:
		return 2
	case CheckTool:
		return 1
	default:
		return 0
	}
}

// Check is the check that raised a finding, and the one that verifies its fix.
// Ref names the instance of the check. For a predicate it is the predicate
// type, for a scan it is the ID of the mission run, and for a tool it is the
// reference of the tool of the buyer.
type Check struct {
	Kind CheckKind `json:"kind"`
	Ref  string    `json:"ref,omitempty"`
}

// Validate returns ErrNoCheck when the kind is not valid, or when a predicate
// or a tool has no ref. A scan may have no ref: a finding that came from outside
// a mission names no mission run.
func (c Check) Validate() error {
	if !c.Kind.IsValid() {
		return fmt.Errorf("%w: kind %q", ErrNoCheck, c.Kind)
	}
	if c.Ref == "" && c.Kind != CheckScan {
		return fmt.Errorf("%w: a %s check needs a ref", ErrNoCheck, c.Kind)
	}
	return nil
}

// CanVerify reports whether a rerun of c may verify a finding that other
// raised. A stronger check can verify and a weaker check cannot. Equal checks
// can verify.
func (c Check) CanVerify(other Check) bool {
	return c.Kind.strength() >= other.Kind.strength() && other.Kind.IsValid()
}

// ScanCheck is the check of a finding that a scan, or a mission run, raised.
// The ref is the mission ID, and it may be empty.
func ScanCheck(missionID types.ID) Check {
	return Check{Kind: CheckScan, Ref: missionID.String()}
}
