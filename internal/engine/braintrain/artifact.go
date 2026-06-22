// Package braintrain is the offline batch trainer for the belief field (ADR-0006,
// gibson#753). It consumes a tenant's brain Timeline — auto-outcomes (mission
// results folded into the World) plus HITL labels — fits the belief network's
// CPTs by smoothed counting, and ships a NEW versioned PER-TENANT model artifact
// in the exact on-disk format the pgmpy sidecar loads (ADR-0005, gibson#750).
//
// This is strictly OUT-OF-BAND. It never runs in the daemon hot path and never
// mutates a live World (online learning would drift the field mid-mission and
// break deterministic replay — ADR-0005). It is a pure transform: events in,
// versioned artifact out, so it is unit-testable with no pgmpy and no sidecar.
//
// Tenant isolation is structural: the trainer is handed ONE tenant's Timeline and
// emits an artifact named `tenant-<id>-v<n>` for that tenant only. Labels never
// cross tenants and never feed the curated commercial base model (ADR-0006 §6).
package braintrain

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// Artifact is the on-disk belief-model JSON the pgmpy sidecar loads
// (sidecar/belief/models/<version>.json). It mirrors that schema exactly: a
// discrete Bayesian network of binary variables with a CPT per variable. The
// trainer reads a base artifact for STRUCTURE (variables + edges) and rewrites
// the CPT values from tenant data.
type Artifact struct {
	Version     string          `json:"version"`
	Description string          `json:"description,omitempty"`
	Variables   []string        `json:"variables"`
	Edges       [][]string      `json:"edges"`
	CPDs        map[string]*CPD `json:"cpds"`
}

// CPD is one variable's conditional probability table, in the sidecar's column
// layout: values[state][parentAssignment]. A root has no evidence and a single
// column; a child has one column per parent-assignment in row-major (big-endian)
// order over its parents, matching pgmpy TabularCPD.
type CPD struct {
	Evidence     []string    `json:"evidence,omitempty"`
	EvidenceCard []int       `json:"evidence_card,omitempty"`
	Values       [][]float64 `json:"values"`
}

// LoadArtifact reads a model artifact JSON file (e.g. the OSS base-v1 model used
// as the structural template).
func LoadArtifact(path string) (*Artifact, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	var a Artifact
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("decode artifact: %w", err)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// queryVars are the three belief-field components every model MUST expose
// (mirrors sidecar/belief/model.py QUERY_VARS).
var queryVars = []string{"juicy", "exploitable", "reachable"}

func (a *Artifact) validate() error {
	have := map[string]bool{}
	for _, v := range a.Variables {
		have[v] = true
	}
	for _, q := range queryVars {
		if !have[q] {
			return fmt.Errorf("model %q missing required query var %q", a.Version, q)
		}
	}
	for v := range a.CPDs {
		if !have[v] {
			return fmt.Errorf("model %q has CPD for unknown variable %q", a.Version, v)
		}
	}
	return nil
}

// Write serialises the artifact to path as indented JSON (matching the committed
// base-v1.json style so artifacts diff cleanly).
func (a *Artifact) Write(path string) error {
	if err := a.validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("encode artifact: %w", err)
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

// parents returns each variable's parent list, derived from edges, in declared
// order (so the CPT column order is deterministic and matches pgmpy's).
func (a *Artifact) parents() map[string][]string {
	out := map[string][]string{}
	for _, v := range a.Variables {
		out[v] = nil
	}
	for _, e := range a.Edges {
		if len(e) != 2 {
			continue
		}
		out[e[1]] = append(out[e[1]], e[0])
	}
	// Stable order within a variable's parents (edges already declare them, but
	// sort for total determinism independent of edge listing order).
	for v := range out {
		sort.Strings(out[v])
	}
	return out
}
