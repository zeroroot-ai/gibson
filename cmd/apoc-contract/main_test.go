// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

func TestWriteRendersTheContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apoc.env")
	if err := write(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // a path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != dataplane.ContractEnv() {
		t.Fatalf("file differs from ContractEnv():\n%s", got)
	}
	if err := write(filepath.Join(t.TempDir(), "missing", "apoc.env")); err == nil {
		t.Fatal("a path whose directory does not exist must fail")
	}
}
