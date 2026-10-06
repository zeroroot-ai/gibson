// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

// UninformativeBetaAlpha and UninformativeBetaBeta are the cold-start Beta
// prior of a learned strength (ADR-0137): the uniform Beta(1,1), mean 0.5.
// The runtime grounds a strength with no fitted posterior at this prior, and
// the trainer (braintrain/fit) adds its outcome counts to this prior. Both
// read the numbers here, so the prior of a fit and the cold start of the
// runtime are the same numbers.
//
// ADR-0137 names Beta(1,1) and the Jeffreys Beta(1/2,1/2) as the two
// defensible uninformative choices, both mean 0.5. Beta(1,1) is the choice
// because BAMCP samples this prior on each rollout rather than only reading
// its mean: Jeffreys is U-shaped, which would make an untrained edge type's
// sampled strength swing to the extremes far more often than the flat prior.
const (
	UninformativeBetaAlpha = 1.0
	UninformativeBetaBeta  = 1.0
)
