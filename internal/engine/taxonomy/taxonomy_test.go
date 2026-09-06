// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package taxonomy

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The identifier constraint is the security control (see the package doc).
// ---------------------------------------------------------------------------

// TestValidIdentifierRejectsNonIdentifiers pins the constraint against the
// shapes that matter, the backtick first: APOC's Util.quote backticks a
// non-identifier without escaping backticks inside it, so a label carrying one
// reaches Neo4j as query structure and the call returns no rows and no error.
func TestValidIdentifierRejectsNonIdentifiers(t *testing.T) {
	bad := map[string]string{
		"backtick":               "Ho`st",
		"backtick escape":        "a` {} //",
		"label injection":        "Host` REMOVE n:Host //",
		"cypher fragment":        "; MATCH (n) DETACH DELETE n",
		"colon":                  "Host:Port",
		"space":                  "Open Port",
		"leading digit":          "2Host",
		"leading underscore":     "_Host",
		"empty":                  "",
		"hyphen":                 "host-v2",
		"dot":                    "graph.Host",
		"quote":                  `Ho"st`,
		"newline":                "Host\nPort",
		"null byte":              "Host\x00",
		"non-ascii":              "Hôst",
		"unicode confusable":     "Ｈost",
		"over the length cap":    strings.Repeat("H", MaxIdentifierBytes+1),
		"brace":                  "Host{}",
		"paren":                  "Host()",
		"bracket":                "Host[]",
		"dollar param":           "$label",
		"comment":                "Host//",
		"backslash":              `Host\`,
		"whitespace only":        " ",
		"trailing space":         "Host ",
		"combining mark":         "Host́",
		"zero width":             "Ho\u200bst",
		"right-to-left override": "Host\u202e",
	}
	for name, label := range bad {
		t.Run(name, func(t *testing.T) {
			if err := ValidIdentifier(label); err == nil {
				t.Fatalf("ValidIdentifier(%q) accepted a non-identifier", label)
			}
		})
	}
}

func TestValidIdentifierAcceptsIdentifiers(t *testing.T) {
	good := []string{
		"Host", "Port", "Observation", "AgentRun", "LlmCall",
		"HAS_PORT", "RUNS_SERVICE", "DELEGATED_TO",
		"a", "Z", "Host2", "host_v2", "A_1",
		strings.Repeat("H", MaxIdentifierBytes),
	}
	for _, label := range good {
		if err := ValidIdentifier(label); err != nil {
			t.Errorf("ValidIdentifier(%q) rejected a plain identifier: %v", label, err)
		}
	}
}

// TestNewRefusesANonIdentifierEntry is the mutation target the issue calls for:
// a Taxonomy that admits a non-identifier label must not build.
func TestNewRefusesANonIdentifierEntry(t *testing.T) {
	t.Run("node label", func(t *testing.T) {
		_, err := New(1, []string{ObservationLabel, "Ho`st"}, nil)
		if err == nil {
			t.Fatal("New admitted a node label carrying a backtick; the identifier " +
				"constraint is what makes Taxonomy membership imply safety")
		}
	})

	t.Run("relationship type", func(t *testing.T) {
		_, err := New(1, []string{ObservationLabel}, []string{"HAS`PORT"})
		if err == nil {
			t.Fatal("New admitted a relationship type carrying a backtick")
		}
	})

	t.Run("duplicate label", func(t *testing.T) {
		if _, err := New(1, []string{ObservationLabel, "Host", "Host"}, nil); err == nil {
			t.Fatal("New admitted a duplicate node label")
		}
	})

	t.Run("Observation must be admitted", func(t *testing.T) {
		if _, err := New(1, []string{"Host"}, nil); err == nil {
			t.Fatal("New built a Taxonomy with no Observation fallback")
		}
	})

	t.Run("duplicate relationship type", func(t *testing.T) {
		if _, err := New(1, []string{ObservationLabel}, []string{"HAS_PORT", "HAS_PORT"}); err == nil {
			t.Fatal("New admitted a duplicate relationship type")
		}
	})

	t.Run("version must be positive", func(t *testing.T) {
		// A zero version is the Go zero value, so accepting it would let an
		// unset version look like a real one on a node's taxonomy_version
		// property — the field Sensing reads to know which vocabulary a
		// projection was written against.
		for _, v := range []int{0, -1} {
			if _, err := New(v, []string{ObservationLabel}, nil); err == nil {
				t.Fatalf("New admitted version %d", v)
			}
		}
	})
}

// TestMustNewPanicsOnAnInvalidTaxonomy states what the package's init does with
// a bad promotion: the process does not start. Without this the only proof is
// the init itself, which cannot be observed from a passing test run.
func TestMustNewPanicsOnAnInvalidTaxonomy(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustNew returned for a Taxonomy New refuses")
		}
	}()
	_ = mustNew(1, []string{"Ho`st"}, nil)
}

// TestGlobalTaxonomyIsAllPlainIdentifiers is the invariant that lets the rest of
// the system trust a classified label without re-checking it. Mutating
// coreNodeLabels or coreRelationshipTypes to admit a non-identifier makes the
// package's init panic and takes every test in this file down with it; this
// test states the property explicitly so the reason is legible.
func TestGlobalTaxonomyIsAllPlainIdentifiers(t *testing.T) {
	for _, label := range Global.NodeLabels() {
		if err := ValidIdentifier(label); err != nil {
			t.Errorf("global Taxonomy node label %q is not a plain identifier: %v", label, err)
		}
	}
	for _, relType := range Global.RelationshipTypes() {
		if err := ValidIdentifier(relType); err != nil {
			t.Errorf("global Taxonomy relationship type %q is not a plain identifier: %v", relType, err)
		}
	}
	if Global.Version() != Version {
		t.Errorf("Global.Version() = %d, want %d", Global.Version(), Version)
	}
}

// TestEveryClassifiableLabelIsSafe closes the loop: whatever a caller asks for,
// the label ClassifyNode hands back is always a plain identifier — so no
// caller-influenced string can reach Neo4j as query structure through this
// package.
func TestEveryClassifiableLabelIsSafe(t *testing.T) {
	hostile := []string{
		"Ho`st", "; MATCH (n) DETACH DELETE n", "Host` REMOVE n:Host //",
		"", " ", "Host:Port", strings.Repeat("H", 4096), "$label", "Hôst",
	}
	for _, requested := range hostile {
		d := Global.ClassifyNode(requested)
		if d.InTaxonomy {
			t.Errorf("ClassifyNode(%q) admitted a hostile label into the Taxonomy", requested)
		}
		if err := ValidIdentifier(d.Label); err != nil {
			t.Errorf("ClassifyNode(%q) returned unsafe label %q: %v", requested, d.Label, err)
		}
		if d.Requested != requested {
			t.Errorf("ClassifyNode(%q) lost the requested shape: got %q", requested, d.Requested)
		}
	}
}

// ---------------------------------------------------------------------------
// The gate: in-taxonomy is typed, out-of-taxonomy is an Observation, and
// nothing is ever rejected.
// ---------------------------------------------------------------------------

func TestClassifyNode(t *testing.T) {
	t.Run("a promoted shape is typed", func(t *testing.T) {
		d := Global.ClassifyNode("Host")
		if !d.InTaxonomy {
			t.Fatalf("Host is not in the Taxonomy: %s", d.Reason)
		}
		if d.Label != "Host" {
			t.Errorf("Label = %q, want Host", d.Label)
		}
		if d.Reason != "" {
			t.Errorf("an admitted shape carries a fallback reason: %q", d.Reason)
		}
	})

	t.Run("a novel shape becomes an Observation", func(t *testing.T) {
		d := Global.ClassifyNode("KubernetesServiceAccount")
		if d.InTaxonomy {
			t.Fatal("a shape nobody promoted was admitted to the Taxonomy")
		}
		if d.Label != ObservationLabel {
			t.Errorf("Label = %q, want %q", d.Label, ObservationLabel)
		}
		if !strings.Contains(d.Reason, "KubernetesServiceAccount") {
			t.Errorf("Reason %q does not name the shape that fell back", d.Reason)
		}
		if d.Requested != "KubernetesServiceAccount" {
			t.Errorf("Requested = %q; the residue must be preserved", d.Requested)
		}
	})

	t.Run("case variants do not silently unify", func(t *testing.T) {
		// Host / HOST / host_v2 diverging unnoticed is the exact failure a
		// global Taxonomy exists to prevent, so only the promoted spelling is
		// admitted and the others land as Observations.
		for _, variant := range []string{"HOST", "host", "host_v2", "Hosts"} {
			if Global.ClassifyNode(variant).InTaxonomy {
				t.Errorf("%q was admitted as though it were Host", variant)
			}
		}
	})
}

func TestClassifyRelationship(t *testing.T) {
	if d := Global.ClassifyRelationship("HAS_PORT"); !d.InTaxonomy {
		t.Errorf("HAS_PORT is not in the Taxonomy: %s", d.Reason)
	}
	d := Global.ClassifyRelationship("PWNED_VIA")
	if d.InTaxonomy {
		t.Fatal("an unpromoted relationship type was admitted")
	}
	if d.Label != ObservationLabel {
		t.Errorf("Label = %q, want %q", d.Label, ObservationLabel)
	}
}

// TestClassifyNeverRejects states the property in its own right: there is no
// input for which the gate produces an error or an empty label.
func TestClassifyNeverRejects(t *testing.T) {
	inputs := []string{
		"", " ", "Host", "HOST", "Ho`st", "; DROP", strings.Repeat("x", 10000),
		"\x00", "\n", "Hôst", "$p", "0", "_",
	}
	for _, in := range inputs {
		for _, d := range []Decision{Global.ClassifyNode(in), Global.ClassifyRelationship(in)} {
			if d.Label == "" {
				t.Errorf("classifying %q produced an empty label; a shape must never be lost", in)
			}
			if !d.InTaxonomy && d.Reason == "" {
				t.Errorf("classifying %q fell back without saying why", in)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Content hash: recurrence detection, not identity.
// ---------------------------------------------------------------------------

func TestContentHash(t *testing.T) {
	t.Run("is stable across map iteration order", func(t *testing.T) {
		want := ContentHash("ServiceAccount", map[string]string{"a": "1", "b": "2", "c": "3"})
		for range 32 {
			got := ContentHash("ServiceAccount", map[string]string{"c": "3", "b": "2", "a": "1"})
			if got != want {
				t.Fatalf("hash is not order-independent: %s != %s", got, want)
			}
		}
	})

	t.Run("distinguishes shape", func(t *testing.T) {
		p := map[string]string{"name": "default"}
		if ContentHash("ServiceAccount", p) == ContentHash("Namespace", p) {
			t.Fatal("two different shapes hash the same")
		}
	})

	t.Run("distinguishes payload", func(t *testing.T) {
		a := ContentHash("S", map[string]string{"name": "default"})
		b := ContentHash("S", map[string]string{"name": "kube-system"})
		if a == b {
			t.Fatal("two different payloads hash the same")
		}
	})

	t.Run("separators inside keys and values cannot forge a match", func(t *testing.T) {
		a := ContentHash("S", map[string]string{"a": "1|b=2"})
		b := ContentHash("S", map[string]string{"a": "1", "b": "2"})
		if a == b {
			t.Fatal("a value containing the field separator forged another observation's hash")
		}
	})

	t.Run("empty payload still hashes", func(t *testing.T) {
		if ContentHash("S", nil) == "" {
			t.Fatal("nil payload produced no hash")
		}
		if ContentHash("S", nil) != ContentHash("S", map[string]string{}) {
			t.Fatal("nil and empty payloads hash differently")
		}
	})
}
