// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package jobnode

import jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"

// CountermeasureContextKey is the key in JobSpec.context that holds the
// countermeasure that the fix of the job applies (gibson#1487). The value is a
// string: the id of the countermeasure in the D3FEND pack, for example
// "D3-FA". The agent that plans the fix writes it after it reads the
// countermeasures of the technique of the finding. A job with no technique has
// no key.
const CountermeasureContextKey = "countermeasure"

// countermeasureOf returns the countermeasure that the spec names, or "".
func countermeasureOf(spec *jobpb.JobSpec) string {
	return spec.GetContext()[CountermeasureContextKey].GetStringValue()
}
