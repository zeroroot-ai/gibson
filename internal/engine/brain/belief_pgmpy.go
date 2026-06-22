package brain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// pgmpyBelief is the real BeliefProvider (ADR-0005): it asks a Python **pgmpy
// sidecar** to run exact, read-only Bayesian inference over the attack-path
// network and returns the three posteriors (P(juicy)/P(exploitable)/P(reachable)).
//
// The sidecar is the only place pgmpy (Python) runs; the Go daemon never does
// probability math itself. Inference is exact (VariableElimination) so the field
// is deterministic and replay-reproducible, and read-only — the sidecar never
// learns online (training is a separate offline batch job, ADR-0005 §4).
//
// The provider records the sidecar's reported model version in Belief.Model, so
// each scored host carries the version that produced it and replay reproduces it
// (missions pin their version — see Mission.BeliefModel / MissionProjected).
type pgmpyBelief struct {
	endpoint    string       // sidecar /score URL
	versionURL  string       // sidecar /version URL (derived from endpoint)
	client      *http.Client // bounded timeout; inference is only on evidence change
	version     string       // pinned model version ("" = whatever the sidecar serves)
	priors      PriorProvider
	resolvedVer atomic.Value // cached sidecar default version (string) when unpinned
}

// PriorProvider supplies a prior for a *novel* node the network has no CPT for
// (ADR-0005 §6: "the LLM fills gaps, not the math"). The pgmpy provider passes
// any node the sidecar reports as novel to this seam; the returned priors feed
// the next inference. A nil PriorProvider means novel nodes keep the sidecar's
// uninformed default — the math still runs, just without an LLM-estimated prior.
//
// It is deliberately small and side-effect-free: replay determinism requires the
// prior to be a pure function of the evidence it is given (no clock, no network
// fan-out that varies run-to-run). A live LLM-backed implementation must cache /
// log its estimates through the Timeline to stay reproducible — that wiring is
// out of scope here; the seam exists so the novel-node path is not a dead end.
type PriorProvider interface {
	// PriorFor returns P(juicy)/P(exploitable)/P(reachable) priors in [0,1] for a
	// node the model has no table for, keyed by the node's evidence fingerprint.
	PriorFor(node NovelNode) NodePrior
}

// NovelNode describes a node the sidecar could not score because the trained
// network has no CPT covering its evidence shape.
type NovelNode struct {
	HostID   uint64
	Address  string
	Evidence beliefEvidence
	Reason   string // sidecar-supplied note (e.g. "unknown service: foo/9999")
}

// NodePrior is an LLM-estimated prior for a novel node, each value in [0,1].
type NodePrior struct {
	Juicy       float64
	Exploitable float64
	Reachable   float64
}

// beliefEvidence is the deterministic, order-stable evidence the provider sends
// to the sidecar for one host. It is derived purely from the Host component, so
// the same Host always yields the same request body (and thus the same posterior).
type beliefEvidence struct {
	OpenPorts []int    `json:"open_ports"`
	Services  []string `json:"services"`  // "<port>/<name>", sorted
	Reachable bool     `json:"reachable"` // any open port observed
}

// scoreRequest is the sidecar wire request. Version pins the model so replay
// re-runs against the exact artifact ("" → sidecar's current default).
type scoreRequest struct {
	Version  string         `json:"version,omitempty"`
	Evidence beliefEvidence `json:"evidence"`
	// Priors lets the caller inject LLM-estimated priors for nodes the model had
	// no table for on a previous pass (keyed by node label). Empty on first pass.
	Priors map[string]NodePrior `json:"priors,omitempty"`
}

// scoreResponse is the sidecar wire response. Version is the artifact that
// actually answered (so the provider records what ran, not what it asked for).
type scoreResponse struct {
	Version     string      `json:"version"`
	Juicy       float64     `json:"juicy"`
	Exploitable float64     `json:"exploitable"`
	Reachable   float64     `json:"reachable"`
	Novel       []NovelNode `json:"novel,omitempty"`
}

// PgmpyBeliefProvider returns a BeliefProvider backed by the pgmpy sidecar at
// endpoint (e.g. "http://127.0.0.1:8087/score"). version pins the model artifact
// the sidecar must use ("" → the sidecar's current default). priors (optional)
// supplies LLM priors for novel nodes; nil disables that path.
func PgmpyBeliefProvider(endpoint, version string, priors PriorProvider) BeliefProvider {
	return &pgmpyBelief{
		endpoint:   endpoint,
		versionURL: deriveVersionURL(endpoint),
		version:    version,
		priors:     priors,
		// Bounded: inference fires only on evidence change, never per tick, so a
		// short timeout is safe and keeps a wedged sidecar from stalling a sweep.
		client: &http.Client{Timeout: 2 * time.Second},
	}
}

// deriveVersionURL maps the /score endpoint to the sidecar's /version endpoint.
func deriveVersionURL(scoreURL string) string {
	if i := strings.LastIndex(scoreURL, "/score"); i >= 0 {
		return scoreURL[:i] + "/version"
	}
	return strings.TrimRight(scoreURL, "/") + "/version"
}

// Version returns the model artifact the provider scores against, for mission
// pinning (ADR-0005 §5). A pinned version is returned verbatim; otherwise the
// sidecar's current default is resolved once via /version and cached.
func (p *pgmpyBelief) Version() string {
	if p.version != "" {
		return p.version
	}
	if v, ok := p.resolvedVer.Load().(string); ok && v != "" {
		return v
	}
	v := p.fetchDefaultVersion()
	if v != "" {
		p.resolvedVer.Store(v)
	}
	return v
}

func (p *pgmpyBelief) fetchDefaultVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), p.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.versionURL, nil)
	if err != nil {
		return ""
	}
	res, err := p.client.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ""
	}
	var out struct {
		Default string `json:"default"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return ""
	}
	return out.Default
}

// Score asks the sidecar for the host's posteriors. On any error the host keeps
// its zero Belief (the field stays quiescent rather than emitting a bogus score);
// the caller's System will retry on the next evidence change.
func (p *pgmpyBelief) Score(h Host) Belief {
	ev := evidenceOf(h)
	req := scoreRequest{Version: p.version, Evidence: ev}

	resp, err := p.call(req)
	if err != nil {
		return Belief{} // fail-quiet: no score rather than a wrong score
	}

	// Novel nodes: the model had no table. Ask the prior provider (the LLM seam),
	// then re-score once with the injected priors. A single re-pass keeps the call
	// pattern bounded and deterministic (no unbounded prior/score ping-pong).
	if len(resp.Novel) > 0 && p.priors != nil {
		priors := make(map[string]NodePrior, len(resp.Novel))
		for _, n := range resp.Novel {
			priors[novelKey(n)] = p.priors.PriorFor(n)
		}
		req.Priors = priors
		if r2, err := p.call(req); err == nil {
			resp = r2
		}
	}

	return Belief{
		Juicy:       resp.Juicy,
		Exploitable: resp.Exploitable,
		Reachable:   resp.Reachable,
		Model:       resp.Version,
	}
}

func (p *pgmpyBelief) call(req scoreRequest) (scoreResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return scoreResponse{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.client.Timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return scoreResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	res, err := p.client.Do(httpReq)
	if err != nil {
		return scoreResponse{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return scoreResponse{}, fmt.Errorf("belief sidecar: status %d", res.StatusCode)
	}
	var out scoreResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return scoreResponse{}, err
	}
	return out, nil
}

// evidenceOf derives the deterministic, order-stable belief evidence from a Host.
// Identical Hosts yield identical evidence, so the sidecar's exact inference is
// reproducible across replays.
func evidenceOf(h Host) beliefEvidence {
	var ports []int
	var svcs []string
	for _, port := range h.Ports {
		if !port.Open {
			continue
		}
		ports = append(ports, port.Number)
		if port.Service.Name != "" {
			svcs = append(svcs, fmt.Sprintf("%d/%s", port.Number, port.Service.Name))
		}
	}
	sort.Ints(ports)
	sort.Strings(svcs)
	return beliefEvidence{
		OpenPorts: ports,
		Services:  svcs,
		Reachable: len(ports) > 0,
	}
}

// novelKey is the stable label a novel node is addressed by in the priors map.
func novelKey(n NovelNode) string {
	if n.Address != "" {
		return n.Address
	}
	return fmt.Sprintf("host-%d", n.HostID)
}
