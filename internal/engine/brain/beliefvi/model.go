// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// QueryVars are the three belief-field components every model artifact MUST
// expose (ADR-0129), mirroring model.QUERY_VARS.
var QueryVars = [3]string{"juicy", "exploitable", "reachable"}

// CPDSpec is one artifact-declared conditional probability table, in
// pgmpy's on-disk TabularCPD layout (see CPDToFactor's doc comment).
type CPDSpec struct {
	Values       [][]float64 `json:"values"`
	Evidence     []string    `json:"evidence,omitempty"`
	EvidenceCard []int       `json:"evidence_card,omitempty"`
}

// ModelArtifact is a parsed, versioned model artifact — the on-disk JSON
// mirroring model.ModelArtifact.
type ModelArtifact struct {
	Version   string             `json:"version"`
	Variables []string           `json:"variables"`
	Edges     [][2]string        `json:"edges"`
	CPDs      map[string]CPDSpec `json:"cpds"`
}

// LoadModelArtifact reads and parses a model artifact JSON file.
func LoadModelArtifact(path string) (ModelArtifact, error) {
	// #nosec G304 -- path is an operator-supplied config path (daemon startup
	// flag / GIBSON_BELIEF_MODEL_PATH), never end-user input.
	raw, err := os.ReadFile(path)
	if err != nil {
		return ModelArtifact{}, fmt.Errorf("beliefvi: load model artifact: %w", err)
	}
	return ParseModelArtifact(raw)
}

// ParseModelArtifact parses a model artifact JSON document, mirroring
// model.ModelArtifact.from_dict: every QueryVars entry must be a declared
// variable.
func ParseModelArtifact(raw []byte) (ModelArtifact, error) {
	var art ModelArtifact
	if err := json.Unmarshal(raw, &art); err != nil {
		return ModelArtifact{}, fmt.Errorf("beliefvi: parse model artifact: %w", err)
	}
	known := make(map[string]struct{}, len(art.Variables))
	for _, v := range art.Variables {
		known[v] = struct{}{}
	}
	for _, q := range QueryVars {
		if _, ok := known[q]; !ok {
			return ModelArtifact{}, fmt.Errorf("beliefvi: model %q missing required query var %q", art.Version, q)
		}
	}
	return art, nil
}

// KnownVars returns the artifact's declared variables as a set.
func (a ModelArtifact) KnownVars() map[string]struct{} {
	out := make(map[string]struct{}, len(a.Variables))
	for _, v := range a.Variables {
		out[v] = struct{}{}
	}
	return out
}

// Evidence is the deterministic evidence one host presents to a BeliefModel,
// mirroring the sidecar wire evidence shape (open_ports / services /
// reachable) that model.evidence_to_observations reads.
//
// FindingCritical, FindingHigh and ExploitDemonstrated are the finding-derived
// evidence (gibson#478): a confirmed finding on the host at a severity, and an
// exploit demonstrated against it. They map onto the model's noisy-OR parents
// of exploitable (finding_critical / finding_high / exploit_demonstrated). A
// false cause contributes nothing, so a host with no finding evidence scores
// exactly as it did before gibson#478.
type Evidence struct {
	OpenPorts           []int
	Services            []string // "<port>/<name>"
	Reachable           bool
	FindingCritical     bool
	FindingHigh         bool
	ExploitDemonstrated bool
}

// EvidenceToObservations maps host evidence onto observed network variables,
// mirroring model.evidence_to_observations exactly: obs maps a known network
// variable to its observed state ("true"/"false"); novel lists evidence
// tokens the network has no variable for (ADR-0129: the caller's LLM
// fills these, the math does not guess). Deterministic: identical evidence
// yields identical observations (ports/services are sorted before mapping),
// so exact inference stays replay-reproducible.
func EvidenceToObservations(ev Evidence, knownVars map[string]struct{}) (obs map[string]string, novel []string) {
	obs = make(map[string]string)

	if _, ok := knownVars["reachable"]; ok {
		obs["reachable"] = boolState(ev.Reachable)
	}

	// Finding-derived evidence is always observed when the model declares it
	// (gibson#478), the same as reachable: a noisy-OR cause observed FALSE
	// contributes nothing, which is what keeps a host with no finding evidence
	// byte-identical to the pre-gibson#478 posteriors. A model that does not
	// declare these variables (e.g. an older artifact) simply ignores them.
	if _, ok := knownVars["finding_critical"]; ok {
		obs["finding_critical"] = boolState(ev.FindingCritical)
	}
	if _, ok := knownVars["finding_high"]; ok {
		obs["finding_high"] = boolState(ev.FindingHigh)
	}
	if _, ok := knownVars["exploit_demonstrated"]; ok {
		obs["exploit_demonstrated"] = boolState(ev.ExploitDemonstrated)
	}

	ports := append([]int(nil), ev.OpenPorts...)
	sort.Ints(ports)
	for _, port := range ports {
		v := fmt.Sprintf("port_%d", port)
		if _, ok := knownVars[v]; ok {
			obs[v] = "true"
		} else {
			novel = append(novel, v)
		}
	}

	svcs := append([]string(nil), ev.Services...)
	sort.Strings(svcs)
	for _, svc := range svcs {
		name := svc
		if _, after, ok := strings.Cut(svc, "/"); ok {
			name = after
		}
		v := "svc_" + name
		if _, ok := knownVars[v]; ok {
			obs[v] = "true"
		} else {
			novel = append(novel, v)
		}
	}

	return obs, novel
}

func boolState(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// PosteriorsFromMarginals pulls the three belief-field components out of
// per-variable P(true) marginals, mirroring model.posteriors_from_marginals:
// a missing query var defaults to 0.0 (an unscored component, not a guess).
func PosteriorsFromMarginals(marginals map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(QueryVars))
	for _, v := range QueryVars {
		out[v] = marginals[v]
	}
	return out
}

// NodePrior is an LLM-estimated prior for a novel node (ADR-0129), each
// value in [0,1] — mirrors brain.NodePrior one layer down.
type NodePrior struct {
	Juicy       float64
	Exploitable float64
	Reachable   float64
}

// BeliefModel is the exact-inference wrapper around a ModelArtifact, mirroring
// model.BeliefModel. It builds the factor set once at construction, then
// answers posteriors with variable elimination (exact — Query). Read-only:
// no fit/structure-learning ever runs at runtime.
type BeliefModel struct {
	artifact ModelArtifact
	factors  []Factor
}

// NewBeliefModel builds and validates a BeliefModel from artifact, mirroring
// model.BeliefModel.__init__: CPDs are built into factors in a deterministic
// (sorted-by-variable-name) order — the JSON object's own key order is not
// significant to numpy/pgmpy's answer either, since exact inference's
// tie-break order only bounds elimination cost (see eliminationOrder), never
// the result — then CheckModel and checkEdgesMatchCPDs validate the whole
// set, exactly as the Python constructor does.
func NewBeliefModel(artifact ModelArtifact) (*BeliefModel, error) {
	names := make([]string, 0, len(artifact.CPDs))
	for name := range artifact.CPDs {
		names = append(names, name)
	}
	sort.Strings(names)

	factors := make([]Factor, 0, len(names))
	for _, name := range names {
		spec := artifact.CPDs[name]
		f, err := CPDToFactor(name, spec.Values, spec.Evidence, spec.EvidenceCard)
		if err != nil {
			return nil, err
		}
		factors = append(factors, f)
	}
	if err := CheckModel(factors, artifact.Variables); err != nil {
		return nil, err
	}
	if err := checkEdgesMatchCPDs(artifact); err != nil {
		return nil, err
	}
	return &BeliefModel{artifact: artifact, factors: factors}, nil
}

// checkEdgesMatchCPDs rejects an artifact whose Edges disagree with its CPD
// parents, mirroring model.BeliefModel._check_edges_match_cpds exactly.
// Inference reads parents off the CPDs, so Edges is redundant — which is
// exactly why it must be checked: a stale Edges list is the artifact bug
// most likely to go unnoticed otherwise.
func checkEdgesMatchCPDs(artifact ModelArtifact) error {
	fromEdges := make(map[string]map[string]struct{}, len(artifact.Variables))
	for _, v := range artifact.Variables {
		fromEdges[v] = make(map[string]struct{})
	}
	for _, e := range artifact.Edges {
		parent, child := e[0], e[1]
		if _, ok := fromEdges[child]; !ok {
			return fmt.Errorf("beliefvi: edge names undeclared variable %q", child)
		}
		if _, ok := fromEdges[parent]; !ok {
			return fmt.Errorf("beliefvi: edge names undeclared variable %q", parent)
		}
		fromEdges[child][parent] = struct{}{}
	}

	for varName, spec := range artifact.CPDs {
		declared := make(map[string]struct{}, len(spec.Evidence))
		for _, p := range spec.Evidence {
			declared[p] = struct{}{}
		}
		fromE := fromEdges[varName]
		if !setsEqual(declared, fromE) {
			return fmt.Errorf(
				"beliefvi: model %q: cpd for %q lists parents %v but edges give %v",
				artifact.Version, varName, sortedKeys(declared), sortedKeys(fromE),
			)
		}
	}
	return nil
}

func setsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Version is the model artifact's version string.
func (m *BeliefModel) Version() string { return m.artifact.Version }

// ScoreResult is the three belief-field components plus any novel evidence
// tokens the model had no variable for, mirroring model.BeliefModel.score's
// return shape.
type ScoreResult struct {
	Juicy       float64
	Exploitable float64
	Reachable   float64
	Version     string
	Novel       []string // e.g. "unknown variable: port_9999"
}

// Score runs exact inference and returns the three components plus any
// novel vars, mirroring model.BeliefModel.score exactly.
//
// priors (optional) supplies caller-estimated priors for novel nodes
// (ADR-0129). Mirroring the Python reference's own
// `next(iter(priors.values()))` — a single prior blob is applied regardless
// of how many novel nodes priors names — this picks the lexicographically
// smallest key deterministically (Python dict iteration is insertion-order,
// which this package has no equivalent of and does not need: at most one
// prior blob is ever actually consulted either way, and determinism is what
// ADR-0134 replay requires).
func (m *BeliefModel) Score(ev Evidence, priors map[string]NodePrior) (ScoreResult, error) {
	knownVars := m.artifact.KnownVars()
	obs, novelVars := EvidenceToObservations(ev, knownVars)

	marginals := make(map[string]float64, len(QueryVars))
	for _, q := range QueryVars {
		if state, ok := obs[q]; ok {
			// A query var that is itself directly observed (e.g. reachable)
			// takes its observed value, not a marginalised prior — the
			// evidence IS the answer.
			marginals[q] = 0.0
			if state == "true" {
				marginals[q] = 1.0
			}
			continue
		}
		condEv := make(map[string]string, len(obs))
		for k, v := range obs {
			if k != q {
				condEv[k] = v
			}
		}
		result, err := Query(m.factors, q, condEv)
		if err != nil {
			return ScoreResult{}, err
		}
		marginals[q] = result["true"]
	}

	out := PosteriorsFromMarginals(marginals)

	if len(priors) > 0 {
		merged := priorByLeastKey(priors)
		for _, q := range QueryVars {
			if out[q] != 0.0 {
				continue
			}
			switch q {
			case "juicy":
				out[q] = merged.Juicy
			case "exploitable":
				out[q] = merged.Exploitable
			case "reachable":
				out[q] = merged.Reachable
			}
		}
	}

	novel := make([]string, len(novelVars))
	for i, n := range novelVars {
		novel[i] = "unknown variable: " + n
	}

	return ScoreResult{
		Juicy:       out["juicy"],
		Exploitable: out["exploitable"],
		Reachable:   out["reachable"],
		Version:     m.Version(),
		Novel:       novel,
	}, nil
}

func priorByLeastKey(priors map[string]NodePrior) NodePrior {
	keys := make([]string, 0, len(priors))
	for k := range priors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return priors[keys[0]]
}
