// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"os"
	"strings"
	"testing"
)

// TestContractEnvFileIsCurrent is the drift gate between the Go constants
// and the committed apoc.env that version-links reads (gibson#28). A
// constant that moves without `make apoc-contract` fails here, on the PR.
func TestContractEnvFileIsCurrent(t *testing.T) {
	got, err := os.ReadFile("apoc.env")
	if err != nil {
		t.Fatalf("read apoc.env: %v (run `make apoc-contract`)", err)
	}
	if string(got) != ContractEnv() {
		t.Fatalf("apoc.env is stale: the Go constants moved. Run `make apoc-contract` and commit the file, so version-links can fan the change out to the chart.\n--- want\n%s--- have\n%s", ContractEnv(), got)
	}
}

// TestContractEnv_CarriesEveryConstant pins the env names version-links.yaml
// cites and the values behind them.
func TestContractEnv_CarriesEveryConstant(t *testing.T) {
	env := ContractEnv()
	for _, line := range []string{
		"NEO4J_APOC_CORE_JAR_GLOB=" + APOCCoreJarGlob,
		"NEO4J_PLUGINS_DIR=" + Neo4jPluginsDir,
		"NEO4J_PROCEDURE_ALLOWLIST=" + Neo4jProcedureAllowlist,
		"NEO4J_APOC_EXPORT_FILE_ENABLED=false",
		"NEO4J_APOC_IMPORT_FILE_ENABLED=false",
	} {
		if !strings.Contains(env, line+"\n") {
			t.Errorf("apoc.env lacks %q", line)
		}
	}
	// Sorted, so a regeneration is byte-stable.
	var last string
	for _, l := range strings.Split(env, "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if last != "" && l < last {
			t.Fatalf("keys are not sorted: %q after %q", l, last)
		}
		last = l
	}
}
