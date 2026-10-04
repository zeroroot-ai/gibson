// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package targetbind

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Facts and Bindings must come from ONE derivation. Two readings of
// target.host would let a mission author and the tool it dispatches disagree
// about which host was scanned, and the report would not say which was right.
func TestFactsAndBindingsAgree(t *testing.T) {
	tgt := &types.Target{
		ID:   types.NewID(),
		Name: "goat",
		Type: "kubernetes",
		URL:  "https://10.0.0.1:6443/path",
	}

	bound := Bindings(tgt)
	facts := Facts(tgt.ID.String(), tgt.Name, tgt.Type, URLOf(tgt))

	if len(facts) != len(bound) {
		t.Fatalf("Facts has %d entries, Bindings %d — one grew without the other", len(facts), len(bound))
	}
	for k, v := range facts {
		want, ok := bound["target."+k]
		if !ok {
			t.Errorf("Bindings has no target.%s", k)
			continue
		}
		if v != want {
			t.Errorf("target.%s: Facts=%q Bindings=%q — two derivations have drifted", k, v, want)
		}
	}
}

// Env is the same six facts under GIBSON_TARGET_*.
func TestEnvCarriesEverySetFact(t *testing.T) {
	env := Env("id-1", "goat", "kubernetes", "https://10.0.0.1:6443")

	for k, want := range map[string]string{
		"GIBSON_TARGET_ID":     "id-1",
		"GIBSON_TARGET_NAME":   "goat",
		"GIBSON_TARGET_TYPE":   "kubernetes",
		"GIBSON_TARGET_URL":    "https://10.0.0.1:6443",
		"GIBSON_TARGET_HOST":   "10.0.0.1:6443",
		"GIBSON_TARGET_DOMAIN": "10.0.0.1",
	} {
		if got := env[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

// An unset fact is OMITTED, not exported empty. A tool cannot tell "this target
// has no host" from "the platform did not tell me", and the two call for
// opposite behaviour — so the honest answer is absence.
func TestEnvOmitsAnUnsetFactRatherThanExportingItEmpty(t *testing.T) {
	env := Env("id-1", "", "", "")

	if _, ok := env["GIBSON_TARGET_ID"]; !ok {
		t.Error("GIBSON_TARGET_ID is missing; it was set")
	}
	for _, k := range []string{
		"GIBSON_TARGET_NAME", "GIBSON_TARGET_TYPE",
		"GIBSON_TARGET_URL", "GIBSON_TARGET_HOST", "GIBSON_TARGET_DOMAIN",
	} {
		if v, ok := env[k]; ok {
			t.Errorf("%s is present with %q; an unset fact must be omitted", k, v)
		}
	}
}

// Every key is namespaced, so merging into a tool's environment cannot shadow
// something the executor or the image set.
func TestEnvNamespacesEveryKey(t *testing.T) {
	for k := range Env("id-1", "goat", "kubernetes", "https://h:1") {
		if !strings.HasPrefix(k, EnvPrefix) {
			t.Errorf("key %q is outside the %s namespace", k, EnvPrefix)
		}
	}
}

// URLOf keeps the two-field precedence binding already used: URL first, then
// Connection["url"]. Older records set only one.
func TestURLOfPrecedence(t *testing.T) {
	cases := []struct {
		name   string
		target types.Target
		want   string
	}{
		{"URL wins", types.Target{URL: "https://u", Connection: map[string]any{"url": "https://c"}}, "https://u"},
		{"then Connection", types.Target{Connection: map[string]any{"url": "https://c"}}, "https://c"},
		{"neither", types.Target{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := URLOf(&c.target); got != c.want {
				t.Errorf("URLOf = %q, want %q", got, c.want)
			}
		})
	}
}
