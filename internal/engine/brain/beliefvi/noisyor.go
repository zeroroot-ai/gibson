// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import "fmt"

// NoisyOrCause is one independent cause in a noisy-OR CPD, mirroring
// noisy_or.NoisyOrCause. Parent is the GROUND (fully-qualified) name of the
// causing variable — noisy-OR does not care whether it is this node's own
// variable (an intra-node dependency) or another node's variable reached
// over an enablement edge (see ground.go); both are just independent causes
// of the same effect. Strength is P(variable=true caused by this parent
// alone, i.e. with every other cause and the leak both absent), in [0, 1].
type NoisyOrCause struct {
	Parent   string
	Strength float64
}

// NoisyOrFactors builds the O(len(causes)) noisy-OR decomposition for
// variable, mirroring noisy_or.noisy_or_factors exactly: P(variable=true |
// parents) = 1 - (1-leak) * prod over true parents of (1 - strength_i),
// reformulated as one binary MECHANISM variable per cause (active with
// probability strength exactly when its cause is true), one LEAK mechanism
// (active unconditionally with probability leak), and a deterministic
// pairwise OR chain combining every mechanism into variable — an EXACT
// reformulation (marginalising the auxiliary variables out reproduces the
// noisy-OR closed form exactly), never an O(2**N) table.
//
// Exactly one returned factor owns variable (its first axis) — the last
// OR-gate in the chain — so a caller merging this into a larger factor set
// (ground.go) can treat the return value as "the CPD for variable" the same
// way it would treat a single CPDToFactor result.
//
// Naming: the auxiliary variables this function introduces are
// "<variable>__leak", "<variable>__z<i>" (the i-th cause's mechanism) and
// "<variable>__or<i>" (the i-th OR-chain accumulator), so two calls for two
// different variables can never collide.
func NoisyOrFactors(variable string, causes []NoisyOrCause, leak float64) ([]Factor, error) {
	if leak < 0.0 || leak > 1.0 {
		return nil, fmt.Errorf("beliefvi: leak must be in [0, 1], got %v", leak)
	}
	for _, c := range causes {
		if c.Strength < 0.0 || c.Strength > 1.0 {
			return nil, fmt.Errorf("beliefvi: cause %q strength must be in [0, 1], got %v", c.Parent, c.Strength)
		}
	}

	leakVar := variable + "__leak"
	if len(causes) == 0 {
		// No causes at all: variable is just the leak's Bernoulli prior —
		// naming it `variable` directly rather than leakVar keeps the
		// zero-cause case a single, ordinary prior factor.
		f, err := NewFactor([]string{variable}, []float64{1.0 - leak, leak})
		if err != nil {
			return nil, err
		}
		return []Factor{f}, nil
	}

	factors := make([]Factor, 0, 1+2*len(causes))
	leakFactor, err := NewFactor([]string{leakVar}, []float64{1.0 - leak, leak})
	if err != nil {
		return nil, err
	}
	factors = append(factors, leakFactor)

	mechanisms := make([]string, len(causes))
	for i, cause := range causes {
		z := fmt.Sprintf("%s__z%d", variable, i)
		mechanisms[i] = z
		// table[z_state][parent_state]: the mechanism can only fire when its
		// cause is true, and then fires with probability `strength`.
		f, err := NewFactor([]string{z, cause.Parent}, []float64{
			1.0, 1.0 - cause.Strength,
			0.0, cause.Strength,
		})
		if err != nil {
			return nil, err
		}
		factors = append(factors, f)
	}

	// Deterministic pairwise OR chain: acc_0 = leak_var; acc_i = OR(acc_{i-1}, z_i).
	// The final accumulator IS `variable` itself. orTable is indexed
	// [out][acc][z] (out is the factor's own variable, axis 0).
	orTable := []float64{
		1, 0, // out=false: acc=0,z=0 -> 1 ; acc=0,z=1 -> 0
		0, 0, // acc=1,z=0 -> 0 ; acc=1,z=1 -> 0
		0, 1, // out=true: acc=0,z=0 -> 0 ; acc=0,z=1 -> 1
		1, 1, // acc=1,z=0 -> 1 ; acc=1,z=1 -> 1
	}

	acc := leakVar
	for i, z := range mechanisms {
		isLast := i == len(mechanisms)-1
		out := fmt.Sprintf("%s__or%d", variable, i)
		if isLast {
			out = variable
		}
		f, err := NewFactor([]string{out, acc, z}, append([]float64(nil), orTable...))
		if err != nil {
			return nil, err
		}
		factors = append(factors, f)
		acc = out
	}

	return factors, nil
}
