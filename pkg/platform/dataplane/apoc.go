// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"sort"
	"strings"
)

// APOC Core provisioning contract for tenant Neo4j (ADR-0012, gibson#1257).
//
// The graph projector shapes nodes with `apoc.merge.node`, which takes labels
// as runtime arguments rather than query text — so a label is data and cannot
// alter query structure. That makes APOC Core a REQUIRED plugin on every tenant
// Neo4j, and it makes the exact plugin+allowlist wiring part of the contract
// between the operator that provisions the database and the daemon that writes
// to it. Both sides read the constants below so the two cannot drift.
//
// # Why the plugin is installed by copy and NOT with NEO4J_PLUGINS
//
// The obvious way to install APOC Core in the official image is
// `NEO4J_PLUGINS='["apoc"]'`. Do not use it. The image's entrypoint reads
// /startup/neo4j-plugins.json, whose "apoc" entry carries
//
//	"properties": { "dbms.security.procedures.unrestricted": "apoc.*" }
//
// and `apply_plugin_default_configuration` appends exactly that line to
// neo4j.conf. Verified against neo4j:5.26.27-community: a container started
// with NEO4J_PLUGINS='["apoc"]' and nothing else reports
// `dbms.security.procedures.unrestricted = apoc.*`. That is the one setting
// ADR-0012 says is never set, and it cannot be reversed by an environment
// variable — plugin installation runs BEFORE the NEO4J_-prefixed settings are
// applied, and the entrypoint skips empty-valued env vars, so there is no way
// to blank it back out.
//
// Unrestricted matters here more than it usually would: Neo4j Community has no
// in-database RBAC, so the setting applies to every connection holding the
// credential — the same credential the projector uses, on a platform whose
// input is attacker-influenced. It turns a graph-write bug into a cluster
// pivot.
//
// So the jar is copied out of the image's own labs directory instead. That is
// also the only option that works once CNI policy enforcement is enabled: the
// tenant Neo4j NetworkPolicy (gibson#1263) permits egress to DNS and nothing
// else, and NEO4J_PLUGINS' fallback path downloads the jar over the internet.
const (
	// APOCCoreJarGlob is where the official Neo4j image ships the APOC Core
	// jar (e.g. /var/lib/neo4j/labs/apoc-5.26.27-core.jar). Copying from
	// here keeps the plugin version locked to the server version and needs
	// no network.
	APOCCoreJarGlob = "/var/lib/neo4j/labs/apoc-*-core.jar"

	// Neo4jPluginsDir is the directory Neo4j loads plugins from. The image
	// entrypoint points server.directories.plugins at /plugins whenever that
	// directory exists, which it does because the pod mounts an emptyDir
	// there.
	Neo4jPluginsDir = "/plugins"

	// Neo4jProcedureAllowlist is the exact value of
	// dbms.security.procedures.allowlist on every tenant Neo4j.
	//
	// These two procedures and nothing else. Everything APOC can do with the
	// filesystem or the network — apoc.export.*, apoc.load.*,
	// apoc.cypher.runFile — is absent from this list and is therefore never
	// registered with the database; calling one fails with "no procedure with
	// the name ... registered", not with a permission error.
	//
	// Consequence, recorded in ADR-0012 and NOT a bug to be fixed here:
	// gibson-backup needs apoc.export.* and therefore stays non-functional.
	// It already degrades to "store skipped"; that remains true and visible.
	// Enabling export reintroduces the pivot above and needs its own ADR.
	//
	// The allowlist governs extensions loaded from the plugins directory, not
	// Neo4j's built-in db.* / dbms.* procedures — those keep working. Verified
	// on 5.26.27: with this allowlist, `CALL dbms.components()` succeeds and
	// `SHOW PROCEDURES` lists exactly the two names below under `apoc`.
	Neo4jProcedureAllowlist = "apoc.merge.node,apoc.merge.relationship"
)

// APOCInstallCommand returns the shell command that installs APOC Core into
// destDir by copying it out of the image. The operator runs this in an init
// container; the integration test that proves the resulting database behaves
// as advertised runs the same string, so "how the plugin gets there" is
// asserted rather than assumed.
func APOCInstallCommand(destDir string) string {
	return "cp " + APOCCoreJarGlob + " " + destDir + "/apoc.jar"
}

// Neo4jSecuritySettings returns the procedure-security configuration every
// tenant Neo4j runs with, keyed by setting name.
//
// dbms.security.procedures.unrestricted is deliberately absent and must stay
// absent — see the package comment above. The two apoc.* entries restate
// APOC's own defaults so that flipping either one is a visible diff; the
// allowlist is what actually binds, because a procedure missing from it is
// never registered with the database at all.
func Neo4jSecuritySettings() map[string]string {
	return map[string]string{
		"dbms.security.procedures.allowlist": Neo4jProcedureAllowlist,
		"apoc.export.file.enabled":           "false",
		"apoc.import.file.enabled":           "false",
	}
}

// Neo4jSettingNames returns the keys of Neo4jSecuritySettings in a stable
// order, so callers that render the settings into an ordered structure (a pod
// spec's env list, say) do not produce a different object on every call.
func Neo4jSettingNames() []string {
	settings := Neo4jSecuritySettings()
	names := make([]string, 0, len(settings))
	for name := range settings {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Neo4jSettingEnvVar converts a configuration setting name into the
// environment variable the official Neo4j image reads it from: prefix NEO4J_,
// '_' becomes '__', '.' becomes '_'. The entrypoint reverses this, and routes
// apoc.*-prefixed settings to apoc.conf rather than neo4j.conf.
func Neo4jSettingEnvVar(setting string) string {
	return "NEO4J_" + strings.ReplaceAll(strings.ReplaceAll(setting, "_", "__"), ".", "_")
}
