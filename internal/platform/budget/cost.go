// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package budget

import (
	"fmt"
	"math"
	"strconv"
)

// CostCents turns the cost of a model call, in US dollars as a decimal string,
// into whole cents. A call with a known cost above zero counts at least one
// cent, so a run of small calls is not counted as free. An unknown cost counts
// as zero cents, and the tokens still count.
func CostCents(known bool, usd string) (int64, error) {
	if !known || usd == "" {
		return 0, nil
	}
	v, err := strconv.ParseFloat(usd, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, fmt.Errorf("the cost %q is not a number of dollars", usd)
	}
	return int64(math.Ceil(v * 100)), nil
}
