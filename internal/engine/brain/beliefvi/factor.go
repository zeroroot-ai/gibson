// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"fmt"

	"gonum.org/v1/gonum/floats"
)

// States are the binary state labels, fixed so CPT column order is
// deterministic across artifacts. Kept in lockstep with sidecar/belief's
// STATES tuple (model.STATES / infer.STATES) — index 0 is "false", index 1
// is "true".
var States = [2]string{"false", "true"}

// stateIndex returns States' index for state, or -1 if state is not a known
// label.
func stateIndex(state string) int {
	for i, s := range States {
		if s == state {
			return i
		}
	}
	return -1
}

// Factor is a discrete factor: an ordered variable tuple plus a dense table.
//
// Table is a flat, row-major ("C order") encoding of the len(Variables)-
// dimensional table every variable in this package has exactly two states
// (see States): Variables[0] is the MOST significant bit of the flat index
// and Variables[len(Variables)-1] is the LEAST significant, mirroring
// infer.py's Factor whose numpy table has one axis per variable in
// Variables order and each axis has length 2. len(Table) is always
// 1<<len(Variables).
type Factor struct {
	Variables []string
	Table     []float64
}

// NewFactor builds a Factor, validating that table's length matches the
// 2**len(variables) a binary-variable factor over variables must have.
func NewFactor(variables []string, table []float64) (Factor, error) {
	want := 1 << len(variables)
	if len(table) != want {
		return Factor{}, fmt.Errorf(
			"beliefvi: factor over %v does not match a %d-entry table (got %d)",
			variables, want, len(table),
		)
	}
	return Factor{Variables: variables, Table: table}, nil
}

// indexOfVariable returns f.Variables' index for name, or -1 if f does not
// carry that variable.
func (f Factor) indexOfVariable(name string) int {
	for i, v := range f.Variables {
		if v == name {
			return i
		}
	}
	return -1
}

// bitsOf decomposes a flat index into n per-axis bits (0 or 1), axis 0 being
// the most-significant bit — the inverse of the packing flatIndex builds.
func bitsOf(idx, n int) []int {
	bits := make([]int, n)
	for i := range n {
		bits[i] = (idx >> (n - 1 - i)) & 1
	}
	return bits
}

// flatIndex packs n per-axis bits (axis 0 most-significant) into a flat
// index — the inverse of bitsOf.
func flatIndex(bits []int) int {
	idx := 0
	for _, b := range bits {
		idx = idx<<1 | b
	}
	return idx
}

// Reduce returns f conditioned on evidence: variables evidence sets are
// SLICED out of the table (their axis is dropped by fixing it at the
// observed state), never summed — which is what makes the result a
// conditional rather than a marginal, exactly mirroring infer.Factor.reduce.
// A variable evidence does not mention is kept as-is. If every one of f's
// variables is observed, the result carries no variables and Table holds
// exactly the one selected scalar.
func (f Factor) Reduce(evidence map[string]string) Factor {
	kept := make([]string, 0, len(f.Variables))
	fixed := make([]int, len(f.Variables)) // -1 = kept (not fixed)
	anyFixed := false
	for i, v := range f.Variables {
		if state, ok := evidence[v]; ok {
			fixed[i] = stateIndex(state)
			anyFixed = true
		} else {
			fixed[i] = -1
			kept = append(kept, v)
		}
	}
	if !anyFixed {
		return f
	}

	n := len(f.Variables)
	newTable := make([]float64, 1<<len(kept))
	for outIdx := range newTable {
		outBits := bitsOf(outIdx, len(kept))
		bits := make([]int, n)
		k := 0
		for i := range n {
			if fixed[i] == -1 {
				bits[i] = outBits[k]
				k++
			} else {
				bits[i] = fixed[i]
			}
		}
		newTable[outIdx] = f.Table[flatIndex(bits)]
	}
	return Factor{Variables: kept, Table: newTable}
}

// expand materialises f's table into shape's variable order, broadcasting
// over any variable in shape that f does not carry (every value along that
// axis is a copy of f's value) — the explicit, materialised equivalent of
// infer.py's _align + numpy broadcasting: the AXIS ORDER changes and any
// variable f lacks is repeated, but no value is otherwise altered.
// Precondition: every variable in f.Variables appears in shape (Multiply's
// only caller establishes this by construction).
func (f Factor) expand(shape []string) []float64 {
	pos := make([]int, len(shape)) // f.Variables index for shape[i], or -1
	for i, v := range shape {
		pos[i] = f.indexOfVariable(v)
	}
	out := make([]float64, 1<<len(shape))
	for outIdx := range out {
		bits := bitsOf(outIdx, len(shape))
		// fBits is f.Variables' own bit vector: bits[i] (shape order) placed
		// at f's axis position for that variable, so the lookup below reads
		// f.Table exactly as f itself is laid out.
		fBits := make([]int, len(f.Variables))
		for i, p := range pos {
			if p >= 0 {
				fBits[p] = bits[i]
			}
		}
		out[outIdx] = f.Table[flatIndex(fBits)]
	}
	return out
}

// Multiply returns the pointwise product of f and other over the union of
// both variable sets: f's own variables first (in f's order), then any of
// other's variables f does not already carry (in other's order) — mirroring
// infer.Factor.multiply's union-then-broadcast construction exactly, so a
// caller never needs to pre-align either factor by hand.
//
// The two tables are first broadcast (expand) into the union's shape, then
// combined with gonum's floats.MulTo, which is the elementwise product this
// package treats as its linear-algebra primitive (a discrete factor product
// is a Hadamard product over the joint state space, not a matrix multiply —
// there is no contraction here, exactly as in the numpy reference, which
// also uses a plain elementwise "*").
func (f Factor) Multiply(other Factor) Factor {
	union := make([]string, 0, len(f.Variables)+len(other.Variables))
	union = append(union, f.Variables...)
	for _, v := range other.Variables {
		if f.indexOfVariable(v) == -1 {
			union = append(union, v)
		}
	}

	a := f.expand(union)
	b := other.expand(union)
	out := make([]float64, len(a))
	floats.MulTo(out, a, b)
	return Factor{Variables: union, Table: out}
}

// SumOut marginalises variable away: the returned factor drops variable's
// axis, each remaining entry the sum of variable's two states, mirroring
// infer.Factor.sum_out. The pairwise sum runs through gonum's floats.Sum,
// this package's other linear-algebra primitive (summation is exactly what
// numpy's ndarray.sum(axis=...) does in the Python reference).
func (f Factor) SumOut(variable string) Factor {
	axis := f.indexOfVariable(variable)
	if axis == -1 {
		return f
	}
	n := len(f.Variables)
	kept := make([]string, 0, n-1)
	kept = append(kept, f.Variables[:axis]...)
	kept = append(kept, f.Variables[axis+1:]...)

	newTable := make([]float64, 1<<len(kept))
	for outIdx := range newTable {
		outBits := bitsOf(outIdx, len(kept))
		bits0 := insertBit(outBits, axis, 0)
		bits1 := insertBit(outBits, axis, 1)
		pair := []float64{f.Table[flatIndex(bits0)], f.Table[flatIndex(bits1)]}
		newTable[outIdx] = floats.Sum(pair)
	}
	return Factor{Variables: kept, Table: newTable}
}

// insertBit returns a copy of bits with value inserted at position axis
// (shifting bits at and after axis one place right), for reconstructing the
// full-axis bit vector SumOut's kept-axis index does not carry.
func insertBit(bits []int, axis, value int) []int {
	out := make([]int, len(bits)+1)
	copy(out, bits[:axis])
	out[axis] = value
	copy(out[axis+1:], bits[axis:])
	return out
}
