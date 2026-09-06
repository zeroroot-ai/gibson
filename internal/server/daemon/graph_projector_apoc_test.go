// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// The Host projection is the tracer bullet for ADR-0012's "shape via APOC, not
// string-building": labels reach Neo4j as a runtime argument, so a label is
// data and cannot alter query structure.
//
// These are the checks that can be made without a database. The property they
// cannot state on their own — that Neo4j really treats the argument as a label
// name and not as Cypher — is asserted against a real server in
// graph_projector_apoc_integration_test.go.

// upsertHostCypherIsAConstant fails to COMPILE if upsertHostCypher stops being
// a compile-time constant. That is the strongest available form of "no Cypher
// in the write path is assembled from input": a fmt.Sprintf, a strings.Builder
// or a package-level var cannot satisfy it, so the regression is caught by the
// compiler rather than by a string match a determined refactor could dodge.
const upsertHostCypherIsAConstant = upsertHostCypher

// TestHostLabelsTravelAsAParameter pins the mechanism: the query names
// $host_labels, and carries no :Host of its own.
func TestHostLabelsTravelAsAParameter(t *testing.T) {
	t.Parallel()

	if !strings.Contains(upsertHostCypherIsAConstant, "apoc.merge.node($host_labels,") {
		t.Errorf("upsertHostCypher does not call apoc.merge.node with $host_labels:\n%s", upsertHostCypher)
	}
	if strings.Contains(upsertHostCypher, ":Host") {
		t.Errorf("upsertHostCypher still writes the Host label as query text; the whole point of "+
			"apoc.merge.node is that the label is an argument:\n%s", upsertHostCypher)
	}

	params := hostUpsertParams(brain.HostSnapshot{ID: 1, Address: "10.0.0.1"})
	got, ok := params["host_labels"].([]string)
	if !ok {
		t.Fatalf("params[host_labels] = %T, want []string", params["host_labels"])
	}
	if len(got) != 1 || got[0] != "Host" {
		t.Errorf("params[host_labels] = %v, want [Host]", got)
	}
}

// TestTaxonomyLabelsRejectWhatAPOCCannotQuote covers the gap apoc.merge.node
// leaves. APOC back-quotes each label without escaping backticks inside it
// (apoc.util.Util.quote, 5.26), so a label containing one closes the quoting
// early and the rest is parsed as Cypher — silently, with no error and no rows
// returned. Every label the projector emits must therefore be a plain
// identifier.
func TestTaxonomyLabelsRejectWhatAPOCCannotQuote(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"Host", "AgentRun", "Port", "Service", "Observation", "A1_b"} {
		if !safeTaxonomyLabel.MatchString(ok) {
			t.Errorf("taxonomy label %q rejected, but it is a plain identifier", ok)
		}
	}
	for _, bad := range []string{
		"Host`) DETACH DELETE (n) //", // the one that actually escapes APOC's quoting
		"`",
		"Host Label",
		"Host;",
		"Host$x",
		"",
		"1Host",
	} {
		if safeTaxonomyLabel.MatchString(bad) {
			t.Errorf("taxonomy label %q accepted; it is not a plain identifier and apoc.merge.node "+
				"cannot be relied on to neutralise it", bad)
		}
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Error("taxonomyLabels accepted a backtick label; an unsafe taxonomy entry must not " +
					"reach a running daemon")
			}
		}()
		_ = taxonomyLabels("Host`) DETACH DELETE (n) //")
	}()

	// The shipped taxonomy passes its own guard.
	for _, l := range hostLabels {
		if !safeTaxonomyLabel.MatchString(l) {
			t.Errorf("shipped host label %q fails the taxonomy guard", l)
		}
	}
}

// TestHostMergeSemanticsAreUnchanged pins what the conversion had to preserve.
// apoc.merge.node's second argument is the identity; anything that leaks into
// it silently re-keys every existing Host node and duplicates the graph.
func TestHostMergeSemanticsAreUnchanged(t *testing.T) {
	t.Parallel()

	if !strings.Contains(upsertHostCypher, "{brain_id: $id}") {
		t.Errorf("Host identity is no longer brain_id alone; re-keying a merge duplicates every "+
			"already-projected host:\n%s", upsertHostCypher)
	}
	// The same property map for onCreate and onMatch reproduces the
	// unconditional SET this replaced.
	if !strings.Contains(upsertHostCypher, "{brain_id: $id}, $host, $host)") {
		t.Errorf("onCreate and onMatch are no longer the same property map, so a re-projected host "+
			"stops being updated:\n%s", upsertHostCypher)
	}

	h := brain.HostSnapshot{
		ID: 42, ScopeID: "scope-1", Address: "10.0.0.7",
		SSHHostKey: "key", CloudID: "i-123",
		Belief: brain.Belief{Juicy: 0.5}, Attention: 0.25, Surprise: "new port",
	}
	props, ok := hostUpsertParams(h)["host"].(map[string]any)
	if !ok {
		t.Fatalf("params[host] = %T, want map[string]any", hostUpsertParams(h)["host"])
	}
	for key, want := range map[string]any{
		"scope": "scope-1", "address": "10.0.0.7", "ssh_host_key": "key",
		"cloud_id": "i-123", "belief_juicy": 0.5, "attention": 0.25, "surprise": "new port",
	} {
		if props[key] != want {
			t.Errorf("host property %q = %v, want %v", key, props[key], want)
		}
	}
	if params := hostUpsertParams(h); params["id"] != int64(42) {
		t.Errorf("params[id] = %v (%T), want int64(42)", params["id"], params["id"])
	}
}

// TestHostQueryDoesNotVaryWithTheHost is the negative of the above: no part of
// a host snapshot may reach the query text. It fails the moment any field is
// formatted into the Cypher rather than passed as a parameter.
func TestHostQueryDoesNotVaryWithTheHost(t *testing.T) {
	t.Parallel()

	adversarial := brain.HostSnapshot{
		ID:         7,
		ScopeID:    "scope`) DETACH DELETE (n",
		Address:    "'; MATCH (n) DETACH DELETE n //",
		SSHHostKey: "`",
		CloudID:    "$smuggled_parameter",
		Surprise:   "MATCH (n) DETACH DELETE n",
	}
	for _, fragment := range []string{
		adversarial.ScopeID, adversarial.Address, adversarial.SSHHostKey,
		adversarial.CloudID, adversarial.Surprise, "DETACH DELETE",
	} {
		if strings.Contains(upsertHostCypher, fragment) {
			t.Errorf("host-derived text %q appears in the query; the write path assembles Cypher from input", fragment)
		}
	}

	// Everything host-shaped is in the parameters instead.
	props := hostUpsertParams(adversarial)["host"].(map[string]any)
	if props["address"] != adversarial.Address {
		t.Errorf("params[host][address] = %v, want the address verbatim", props["address"])
	}
}
