// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package fit fits the two belief artifacts of one tenant (ADR-0106, ADR-0137,
// gibson#614): the belief-CPT model and the Beta posterior of each enablement
// edge type. It is pure: training data in, artifacts out.
//
// The belief trainer (cmd/belief-trainer) imports this package. The trainer
// talks only to the daemon and opens no data store, so this package imports
// no package that reaches Redis or Postgres. It depends on beliefvi for the
// runtime artifact types only, never on the brain package.
package fit

import (
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
)

// Row is one training example: the binary state of each network variable for
// one observed host. A variable that a row does not name is false: a training
// row names each observed port and service, so a port or a service that the
// row does not name was not seen on that host.
type Row map[string]bool

// basePriorWeight is the weight of the base model in each fitted CPT column,
// counted in rows. Each column starts as basePriorWeight pseudo-rows that
// follow the base model, and the tenant rows add to them. With no row for a
// column the column keeps the base value. Two pseudo-rows are the strength of
// the classic Laplace prior over two states, so one tenant row cannot swing a
// column to 0 or 1.
const basePriorWeight = 2.0

// Fit refits each CPT of base from rows and stamps version on the result. The
// base supplies the structure (variables, edges and the parent order of each
// CPT) and the prior of each column.
func Fit(base beliefvi.ModelArtifact, rows []Row, version string) (beliefvi.ModelArtifact, error) {
	if version == "" {
		return beliefvi.ModelArtifact{}, errors.New("fit: empty version")
	}
	out := beliefvi.ModelArtifact{
		Version:   version,
		Variables: append([]string(nil), base.Variables...),
		Edges:     append([][2]string(nil), base.Edges...),
		CPDs:      make(map[string]beliefvi.CPDSpec, len(base.CPDs)),
	}
	for name, spec := range base.CPDs {
		fitted, err := fitCPD(name, spec, rows)
		if err != nil {
			return beliefvi.ModelArtifact{}, fmt.Errorf("fit: CPT of %q: %w", name, err)
		}
		out.CPDs[name] = fitted
	}
	if _, err := beliefvi.NewBeliefModel(out); err != nil {
		return beliefvi.ModelArtifact{}, fmt.Errorf("fit: the fitted model is not valid: %w", err)
	}
	return out, nil
}

// fitCPD refits one CPT. Its columns enumerate the parent assignments in the
// declared parent order, last parent varying fastest, state 0 false (the
// beliefvi.CPDToFactor layout).
func fitCPD(name string, base beliefvi.CPDSpec, rows []Row) (beliefvi.CPDSpec, error) {
	if len(base.Values) != 2 {
		return beliefvi.CPDSpec{}, fmt.Errorf("fit: variable %q is not binary", name)
	}
	cols := 1 << len(base.Evidence)
	if len(base.Values[0]) != cols || len(base.Values[1]) != cols {
		return beliefvi.CPDSpec{}, fmt.Errorf("fit: variable %q has %d columns, want %d", name, len(base.Values[1]), cols)
	}
	trueCount := make([]float64, cols)
	total := make([]float64, cols)
	for _, r := range rows {
		col := 0
		for _, p := range base.Evidence {
			col <<= 1
			if r[p] {
				col |= 1
			}
		}
		total[col]++
		if r[name] {
			trueCount[col]++
		}
	}
	falseRow := make([]float64, cols)
	trueRow := make([]float64, cols)
	for c := range cols {
		pTrue := round((trueCount[c] + basePriorWeight*base.Values[1][c]) / (total[c] + basePriorWeight))
		trueRow[c] = pTrue
		falseRow[c] = round(1 - pTrue)
	}
	return beliefvi.CPDSpec{
		Values:       [][]float64{falseRow, trueRow},
		Evidence:     append([]string(nil), base.Evidence...),
		EvidenceCard: append([]int(nil), base.EvidenceCard...),
	}, nil
}

// round keeps 4 decimal places: enough for a CPT, and a fit of the same rows
// gives a byte-stable artifact.
func round(f float64) float64 {
	return float64(int64(f*1e4+0.5)) / 1e4
}
