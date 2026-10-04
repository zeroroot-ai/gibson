// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"slices"
	"strings"
)

// MissionSecretScopes is a mission's declaration of which named tenant secrets
// each of its components may be handed at dispatch (gibson#485).
//
// It is the gibson-side value of MissionDefinition.secrets. A value type rather
// than the proto message because the resolution it drives is this package's
// concern and the wire shape is the sdk's: the mission manager translates once,
// at the point it already holds the definition.
//
// NAMES ONLY. A value is never here, never in the mission definition, and never
// named by the component — the daemon resolves it as itself, at dispatch, and
// hands it over as environment. The property ScopeID already has: an
// agent-supplied value would make the decision attacker-influenceable.
//
// This does not widen FGA. `secret.can_resolve` admits only plugin_principal,
// and the non-plugin-secret-isolation spec asserts an agent and a tool are each
// denied. That holds: a component still cannot ASK for a secret. This says what
// the daemon may hand it.
type MissionSecretScopes struct {
	// Mission is handed to every component in the run, whatever its kind.
	Mission []string

	// Agents, Tools and Plugins are handed to every component of that kind.
	Agents  []string
	Tools   []string
	Plugins []string

	// Agent, Tool and Plugin are handed to one NAMED component, keyed by the
	// name the catalog and the mission node spell.
	Agent  map[string][]string
	Tool   map[string][]string
	Plugin map[string][]string
}

// ForTool is the names the named tool may be handed: the union of the
// mission-wide list, the tool-wide list and its own.
//
// A UNION and not a narrowing. "Tool-wide" means every tool sees it, so a
// per-name entry adds to that rather than replacing it — a declaration that
// silently removed access granted one line above would be the kind of rule
// nobody can read off the file. ForAgent and ForPlugin are the same for their
// kinds.
//
// The result is sorted and de-duplicated so a caller's iteration order, and so
// the environment a tool receives, does not depend on map ordering. Two runs of
// one mission must hand a tool the same thing in the same order.
func (s MissionSecretScopes) ForTool(name string) []string {
	return s.union(s.Tools, s.Tool, name)
}

// ForAgent is ForTool for an agent.
func (s MissionSecretScopes) ForAgent(name string) []string {
	return s.union(s.Agents, s.Agent, name)
}

// ForPlugin is ForTool for a plugin.
func (s MissionSecretScopes) ForPlugin(name string) []string {
	return s.union(s.Plugins, s.Plugin, name)
}

func (s MissionSecretScopes) union(kind []string, named map[string][]string, name string) []string {
	out := make([]string, 0, len(s.Mission)+len(kind)+len(named[name]))
	add := func(names []string) {
		for _, n := range names {
			n = strings.TrimSpace(n)
			// An empty name is dropped rather than carried. It can never
			// resolve, and carrying it would turn a typo in a mission file into
			// a lookup failure at dispatch, blamed on the store.
			if n == "" {
				continue
			}
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	add(s.Mission)
	add(kind)
	if name != "" {
		add(named[name])
	}
	slices.Sort(out)
	return out
}

// Declares reports whether the declaration names anything at all. An empty
// declaration hands nothing to anything, which is the behaviour before missions
// could declare secrets.
func (s MissionSecretScopes) Declares() bool {
	if len(s.Mission)+len(s.Agents)+len(s.Tools)+len(s.Plugins) > 0 {
		return true
	}
	for _, m := range []map[string][]string{s.Agent, s.Tool, s.Plugin} {
		for _, v := range m {
			if len(v) > 0 {
				return true
			}
		}
	}
	return false
}
