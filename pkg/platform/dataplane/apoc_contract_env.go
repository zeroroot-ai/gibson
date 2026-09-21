// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"sort"
	"strings"
)

// ContractEnvFile is the committed rendering of this package's Neo4j APOC
// contract in `NAME=value` form (pkg/platform/dataplane/apoc.env). It exists
// for one reader: the org's version-links (zeroroot-ai/.github,
// version-links.yaml), which compares each value with the chart values that
// copy it (helm/gibson/values.yaml in zeroroot-ai/charts) and opens the
// chart PR when one moves. The Go constants stay the source; this file is
// what a cross-repo tool can read. TestContractEnvFileIsCurrent fails when
// the file and the constants disagree; `make apoc-contract` rewrites it
// (gibson#28).
const ContractEnvFile = "pkg/platform/dataplane/apoc.env"

// contractEnvKeys maps each contract value to its env name. The names are
// the ones version-links.yaml cites; renaming one is a change to both.
func contractEnvKeys() map[string]string {
	return map[string]string{
		"NEO4J_APOC_CORE_JAR_GLOB":       APOCCoreJarGlob,
		"NEO4J_PLUGINS_DIR":              Neo4jPluginsDir,
		"NEO4J_PROCEDURE_ALLOWLIST":      Neo4jProcedureAllowlist,
		"NEO4J_APOC_EXPORT_FILE_ENABLED": Neo4jSecuritySettings()["apoc.export.file.enabled"],
		"NEO4J_APOC_IMPORT_FILE_ENABLED": Neo4jSecuritySettings()["apoc.import.file.enabled"],
	}
}

// ContractEnv renders the contract as the env file's content, keys sorted,
// one `NAME=value` per line, with a header that says where it comes from.
func ContractEnv() string {
	keys := contractEnvKeys()
	names := make([]string, 0, len(keys))
	for n := range keys {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# apoc.env: the Neo4j APOC provisioning contract, rendered from the Go\n")
	b.WriteString("# constants in pkg/platform/dataplane/apoc.go. Generated: run `make apoc-contract`.\n")
	b.WriteString("# Read by zeroroot-ai/.github version-links.yaml, which keeps the chart's\n")
	b.WriteString("# copies in zeroroot-ai/charts helm/gibson/values.yaml equal to these (gibson#28).\n")
	for _, n := range names {
		b.WriteString(n)
		b.WriteString("=")
		b.WriteString(keys[n])
		b.WriteString("\n")
	}
	return b.String()
}
