// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import "testing"

func TestFactor_ReduceSlicesOutObservedVariables(t *testing.T) {
	f, err := NewFactor([]string{"a", "b"}, []float64{0.1, 0.2, 0.3, 0.4}) // a=0:{b=0:.1,b=1:.2} a=1:{.3,.4}
	if err != nil {
		t.Fatal(err)
	}
	got := f.Reduce(map[string]string{"a": "true"})
	if len(got.Variables) != 1 || got.Variables[0] != "b" {
		t.Fatalf("expected [b], got %v", got.Variables)
	}
	if got.Table[0] != 0.3 || got.Table[1] != 0.4 {
		t.Fatalf("expected [0.3 0.4], got %v", got.Table)
	}
}

func TestFactor_ReduceToScalarWhenEveryVariableIsObserved(t *testing.T) {
	f, err := NewFactor([]string{"a", "b"}, []float64{0.1, 0.2, 0.3, 0.4})
	if err != nil {
		t.Fatal(err)
	}
	got := f.Reduce(map[string]string{"a": "true", "b": "false"})
	if len(got.Variables) != 0 {
		t.Fatalf("expected no variables, got %v", got.Variables)
	}
	if len(got.Table) != 1 || got.Table[0] != 0.3 {
		t.Fatalf("expected [0.3], got %v", got.Table)
	}
}

func TestFactor_MultiplyIsCommutativeUpToVariableOrder(t *testing.T) {
	a, _ := NewFactor([]string{"x"}, []float64{0.2, 0.8})
	b, _ := NewFactor([]string{"y"}, []float64{0.5, 0.5})
	ab := a.Multiply(b)
	ba := b.Multiply(a)

	want := map[[2]string]float64{}
	for _, xv := range []int{0, 1} {
		for _, yv := range []int{0, 1} {
			want[[2]string{States[xv], States[yv]}] = a.Table[xv] * b.Table[yv]
		}
	}

	for _, f := range []Factor{ab, ba} {
		xi := f.indexOfVariable("x")
		yi := f.indexOfVariable("y")
		for idx, v := range f.Table {
			bits := bitsOf(idx, len(f.Variables))
			key := [2]string{States[bits[xi]], States[bits[yi]]}
			if v != want[key] {
				t.Errorf("factor %v mismatch at %v: got %v want %v", f.Variables, key, v, want[key])
			}
		}
	}
}

func TestFactor_SumOutMarginalisesAnAxis(t *testing.T) {
	f, err := NewFactor([]string{"a", "b"}, []float64{0.1, 0.2, 0.3, 0.4})
	if err != nil {
		t.Fatal(err)
	}
	got := f.SumOut("a")
	if len(got.Variables) != 1 || got.Variables[0] != "b" {
		t.Fatalf("expected [b], got %v", got.Variables)
	}
	// b=false: 0.1(a=f)+0.3(a=t)=0.4 ; b=true: 0.2+0.4=0.6
	approxEqual(t, got.Table[0], 0.4, 1e-12, "b=false")
	approxEqual(t, got.Table[1], 0.6, 1e-12, "b=true")
}

func TestNewFactor_RejectsAMismatchedTable(t *testing.T) {
	if _, err := NewFactor([]string{"a", "b"}, []float64{0.1, 0.2, 0.3}); err == nil {
		t.Fatal("expected an error for a mismatched table length")
	}
}
