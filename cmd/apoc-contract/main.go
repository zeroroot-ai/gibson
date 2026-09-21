// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// apoc-contract writes pkg/platform/dataplane/apoc.env from the Go constants
// (gibson#28). `make apoc-contract` runs it; TestContractEnvFileIsCurrent
// fails a PR whose constants moved without it.
package main

import (
	"fmt"
	"os"

	"github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

func main() {
	if err := write(dataplane.ContractEnvFile); err != nil {
		fmt.Fprintln(os.Stderr, "apoc-contract:", err)
		os.Exit(1)
	}
	fmt.Println("wrote", dataplane.ContractEnvFile)
}

// write renders the contract to path. The file is committed source, so it
// is world-readable like the rest of the tree.
func write(path string) error {
	if err := os.WriteFile(path, []byte(dataplane.ContractEnv()), 0o644); err != nil { //nolint:gosec // a generated, committed source file
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
