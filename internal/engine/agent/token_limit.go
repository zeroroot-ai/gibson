// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agent

// MinLimit returns the smaller of two output token limits. Zero means that
// the limit is unknown, so it never wins over a known limit.
func MinLimit(a, b int32) int32 {
	switch {
	case a <= 0:
		return max(b, 0)
	case b <= 0:
		return a
	default:
		return min(a, b)
	}
}
