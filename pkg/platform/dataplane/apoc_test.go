// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPOCInstallCommand(t *testing.T) {
	got := APOCInstallCommand("/plugins")
	assert.Equal(t, "cp "+APOCCoreJarGlob+" /plugins/apoc.jar", got)
}

func TestNeo4jSecuritySettings(t *testing.T) {
	s := Neo4jSecuritySettings()
	// The procedure allow-list must be exactly the two apoc.merge procedures the
	// projector uses — nothing broader.
	assert.Equal(t, Neo4jProcedureAllowlist, s["dbms.security.procedures.allowlist"])
	assert.Equal(t, "apoc.merge.node,apoc.merge.relationship", s["dbms.security.procedures.allowlist"])
	// File import/export stay disabled: APOC is provisioned for in-graph merge
	// only, not filesystem access.
	assert.Equal(t, "false", s["apoc.export.file.enabled"])
	assert.Equal(t, "false", s["apoc.import.file.enabled"])
}

func TestNeo4jSettingNames_SortedAndComplete(t *testing.T) {
	names := Neo4jSettingNames()
	require.NotEmpty(t, names)
	// Every security setting is named, in deterministic sorted order.
	require.Len(t, names, len(Neo4jSecuritySettings()))
	assert.IsIncreasing(t, names)
	for _, n := range names {
		_, ok := Neo4jSecuritySettings()[n]
		assert.True(t, ok, "%s is named but not a security setting", n)
	}
}

func TestNeo4jSettingEnvVar(t *testing.T) {
	// Neo4j maps a dotted setting to an env var by upper-casing and replacing
	// '.' and '_' per its own convention.
	assert.Equal(t, "NEO4J_dbms_security_procedures_allowlist",
		Neo4jSettingEnvVar("dbms.security.procedures.allowlist"))
	assert.Equal(t, "NEO4J_apoc_export_file_enabled",
		Neo4jSettingEnvVar("apoc.export.file.enabled"))
}
