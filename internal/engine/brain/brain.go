// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package brain is the ECS-native mission brain (epic ecs-brain).
//
// The brain is an Entity-Component-System (ark) per ADR-0101. Its core invariant
// is log-first event sourcing: a per-tenant append-only Timeline of domain events
// is the system of record, and the Tenant World is a fold of that Timeline. A
// single-writer reducer is the only thing that mutates the World; everything else
// emits events and reads snapshots. Replaying the Timeline into a fresh World
// reproduces state exactly.
//
// Entity identity is scope-relative (ADR-0102, gibson#746): the coordinate of a
// host is (ScopeID, Address), and resolution is a scope-partitioned loop-compare
// over strong identity signals — see identity.go.
package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// Host is the host component. Identity is the (ScopeID, Address) coordinate plus
// optional strong signals (SSHHostKey, CloudID) that identify the host across
// addresses. Ports is volatile state (updated-on-match, never compared).
// Placeholder shape; sdk#340 will codegen components from taxonomy/v1.
type Host struct {
	ID         uint64 // stable, replay-deterministic id (assigned at creation) for event references
	ScopeID    string // identity (coordinate)
	Address    string // identity (coordinate, within scope)
	SSHHostKey string // strong identity signal (stable across addresses)
	CloudID    string // strong identity signal
	Ports      []PortObservation
	Belief     Belief // attack-path belief (derived; ADR-0129)
	// CauseEdgeTypes are the enablement-edge types that fed this host in the
	// slice its Belief was scored from (gibson#613): the causes a settled bet
	// on a hypothesis about this host credits or blames. Sorted, unique.
	CauseEdgeTypes []string
	// EvidenceDigest fingerprints the evidence the outstanding belief score was
	// requested for (belief.go). The gate re-requests a score only when the
	// host's current evidence digest differs from this one, and the reducer
	// drops a BeliefScored whose digest no longer matches — the result of a
	// score the evidence has already moved past.
	EvidenceDigest string
	// MissionID is the mission that discovered this host — the mission-evidence edge
	// (gibson#1075). Carried from the observation's ingest context so a mission-scoped
	// frame surfaces the hosts that mission found, and so a surprise→Finding promotion
	// inherits the mission attribution. Empty for a host seen without mission context.
	MissionID string
}

// Surprise marks an entity the model did not expect — here, an identity
// contradiction (an address reused by a different host). It is the input to the
// attention/anomaly signal (ADR-0129/0106); it is not itself a separate entity.
type Surprise struct {
	Reason string
}

// World is a single tenant's in-memory ECS world (ADR-0101: one World per tenant,
// never shared). Only the reducer mutates it.
type World struct {
	Tenant      string
	ecs         *ecs.World
	hosts       *ecs.Map1[Host]
	surprises   *ecs.Map1[Surprise]
	work        *ecs.Map1[WorkItem]
	decisions   *ecs.Map1[DecisionRecord]
	missions    *ecs.Map1[Mission]
	findings    *ecs.Map1[Finding]
	labels      *ecs.Map1[Label]
	domains     *ecs.Map1[Domain]
	subdomains  *ecs.Map1[Subdomain]
	credentials *ecs.Map1[Credential]
	accounts    *ecs.Map1[Account]
	agentRuns   *ecs.Map1[AgentRun]
	llmCalls    *ecs.Map1[LlmCall]
	// agentToolCalls holds the flight recorder's tool-I/O capture (ADR-0120,
	// gibson#271) — the tool-call counterpart to llmCalls.
	agentToolCalls *ecs.Map1[AgentToolCall]
	// flightRecorderPolicy is the tenant's current retention/redaction policy
	// (flight_recorder.go, gibson#271). Not ECS-backed: it is a per-tenant
	// singleton, not a collection of entities.
	flightRecorderPolicy FlightRecorderPolicy

	// domainPacks holds this tenant's currently enabled Domain Packs
	// (domain_pack.go, ADR-0133, gibson#381) — the "live registry" a
	// DomainPackEnabled/Disabled fold maintains. Not ECS-backed: keyed
	// per-tenant state, like flightRecorderPolicy, not a collection of
	// sighted facts.
	domainPacks map[string]DomainPackState

	// missionLineage holds the lineage of each mission that a component
	// originated (mission_lineage.go, gibson#734), keyed by mission id.
	missionLineage map[string]MissionLineage

	// proofReviews holds the latest proof with agent-typed evidence for each
	// hypothesis (proof_review.go, ADR-0131), keyed by hypothesis id.
	proofReviews map[string]BetProofSubmittedForReview

	// ontologyGate is this tenant's taxonomy-discovery safety gate
	// (taxonomy.PromotionGate, ADR-0124, ADR-0133,
	// gibson#391/#392), folded from OntologyExtensionProposed/Approved
	// (ontology_extension.go). Base is taxonomy.Global — the platform's own
	// core Taxonomy — the same base gibson#281's original design classifies
	// sightings against. applyOntologyExtensionApproved (gibson#392) is the
	// only path that ever calls Promote: once a proposal has BOTH recurred
	// taxonomy.MinRecurrenceForSettlement times AND been explicitly approved
	// by the tenant owner, Base() advances to admit the new label — this
	// tenant's live taxonomy extension.
	ontologyGate *taxonomy.PromotionGate

	// ontologyProposals holds this tenant's currently observed ontology/
	// taxonomy extension proposals (ADR-0124, ADR-0133,
	// gibson#391/#392), keyed by (kind, label) — the read model
	// OntologyExtensionService.ListOntologyExtensionProposals (gibson#392)
	// lists from. Not ECS-backed: like domainPacks, per-tenant
	// singleton-shaped state keyed by proposal identity — a repeat sighting
	// of the SAME (kind, label) updates its entry in place rather than
	// adding a new one.
	ontologyProposals map[ontologyProposalKey]OntologyProposalState

	// edgeOutcomes is the per-enablement-edge-type Beta-Bernoulli statistic
	// ADR-0137 learns from (gibson#613), folded from
	// EdgeOutcomeObserved and carried by WorldSnapshot so TrimTo loses none.
	edgeOutcomes map[string]EdgeOutcomeCount

	// missionRewinds holds the parent of each mission that a rewind started
	// (mission_rewind.go, ADR-0170). Keyed by the new mission id.
	missionRewinds map[string]MissionRewind

	// observations holds out-of-taxonomy shapes (ADR-0112). Keyed by Timeline
	// event id rather than by content, so repeat sightings stay distinct.
	observations *ecs.Map1[Observation]

	// entities holds the typed application-lifecycle nodes (gibson#1656),
	// keyed by (Taxonomy label, stable key). See entity.go.
	entities *ecs.Map1[Entity]

	// hypotheses holds the Hypothesis provenance class (ADR-0121, gibson#265):
	// an agent's proposed, unproven claim, keyed by (ScopeID, Claim). See
	// hypothesis.go. Distinct from both Evidence (hosts, domains, ...) and
	// Belief (belief.go) — a Hypothesis is folded and stored separately from
	// both, never derived from or into either.
	hypotheses *ecs.Map1[Hypothesis]

	// betSettlements holds proof-of-demonstration verdicts (ADR-0131,
	// gibson#278), keyed by HypothesisID — the same externally-given-string
	// identity AgentRun uses for RunID, never a derived counter. See
	// bet_settlement.go.
	betSettlements *ecs.Map1[BetSettlement]

	// destructiveActions holds pending/decided destructive-proof
	// authorization records (ADR-0132, gibson#336), keyed by HypothesisID —
	// the same externally-given-string identity BetSettlement uses. See
	// destructive_authz.go.
	destructiveActions *ecs.Map1[DestructiveAction]

	// voiPlans holds each mission's VoI planning state (gibson#283,
	// ADR-0126): whether a plan is in flight, the evidence cursor it answers
	// for, and the last completed plan's ranked, top-k candidates. See
	// voi_planner.go. Standalone, like decisions — never a field on Mission.
	voiPlans *ecs.Map1[VoIPlanState]

	// nodeBeliefs backs BeliefSubstrate (belief_substrate.go, gibson#272) for
	// every node kind that is not its own ECS entity — NodeKindClaim (the
	// market view) and NodeKindTechniqueEnvironment (the reputation view),
	// ADR-0129. Host belief stays on the Host component itself
	// (belief.go); this is the general-purpose store for every other kind.
	// See node_belief.go.
	nodeBeliefs *ecs.Map1[NodeBeliefRecord]

	// next*ID are monotonic, replay-deterministic counters for assigning stable
	// ids (incremented in the single-writer reducer, so replay reproduces ids).
	// Counters are per-entity-type; ids are unique within a (label) namespace,
	// which is all the graph projection needs (nodes are keyed by label + brain_id).
	nextHostID        uint64
	nextDomainID      uint64
	nextSubdomainID   uint64
	nextCredentialID  uint64
	nextAccountID     uint64
	nextObservationID uint64
	nextEntityID      uint64
	nextHypothesisID  uint64
	// nextCompletedSeq counts folded WorkCompleted events (gibson#543).
	nextCompletedSeq uint64
}

func (w *World) newCredentialID() uint64 {
	w.nextCredentialID++
	return w.nextCredentialID
}

func (w *World) newAccountID() uint64 {
	w.nextAccountID++
	return w.nextAccountID
}

func (w *World) newObservationID() uint64 {
	w.nextObservationID++
	return w.nextObservationID
}

func (w *World) newEntityID() uint64 {
	w.nextEntityID++
	return w.nextEntityID
}

// newHypothesisID returns the next stable hypothesis id (single-writer;
// deterministic on replay).
func (w *World) newHypothesisID() uint64 {
	w.nextHypothesisID++
	return w.nextHypothesisID
}

// newHostID returns the next stable host id (single-writer; deterministic on replay).
func (w *World) newHostID() uint64 {
	w.nextHostID++
	return w.nextHostID
}

func (w *World) newDomainID() uint64 {
	w.nextDomainID++
	return w.nextDomainID
}

func (w *World) newSubdomainID() uint64 {
	w.nextSubdomainID++
	return w.nextSubdomainID
}

// NewWorld returns an empty Tenant World.
func NewWorld(tenant string) *World {
	w := ecs.NewWorld()
	return &World{
		Tenant:             tenant,
		ecs:                w,
		hosts:              ecs.NewMap1[Host](w),
		surprises:          ecs.NewMap1[Surprise](w),
		work:               ecs.NewMap1[WorkItem](w),
		decisions:          ecs.NewMap1[DecisionRecord](w),
		missions:           ecs.NewMap1[Mission](w),
		findings:           ecs.NewMap1[Finding](w),
		labels:             ecs.NewMap1[Label](w),
		domains:            ecs.NewMap1[Domain](w),
		subdomains:         ecs.NewMap1[Subdomain](w),
		credentials:        ecs.NewMap1[Credential](w),
		accounts:           ecs.NewMap1[Account](w),
		agentRuns:          ecs.NewMap1[AgentRun](w),
		llmCalls:           ecs.NewMap1[LlmCall](w),
		agentToolCalls:     ecs.NewMap1[AgentToolCall](w),
		observations:       ecs.NewMap1[Observation](w),
		entities:           ecs.NewMap1[Entity](w),
		hypotheses:         ecs.NewMap1[Hypothesis](w),
		betSettlements:     ecs.NewMap1[BetSettlement](w),
		destructiveActions: ecs.NewMap1[DestructiveAction](w),
		voiPlans:           ecs.NewMap1[VoIPlanState](w),
		nodeBeliefs:        ecs.NewMap1[NodeBeliefRecord](w),
		domainPacks:        make(map[string]DomainPackState),
		missionLineage:     make(map[string]MissionLineage),
		proofReviews:       make(map[string]BetProofSubmittedForReview),
		ontologyGate:       taxonomy.NewPromotionGate(taxonomy.Global),
		ontologyProposals:  make(map[ontologyProposalKey]OntologyProposalState),
		edgeOutcomes:       make(map[string]EdgeOutcomeCount),
		missionRewinds:     make(map[string]MissionRewind),
	}
}

// HostSnapshot is a stable, comparable view of a Host for assertions/inspection.
type HostSnapshot struct {
	ID         uint64 // stable, replay-deterministic id — the graph projection key (ADR-0107)
	ScopeID    string
	Address    string
	SSHHostKey string
	CloudID    string
	OpenPorts  []int               // currently-open port numbers, ascending
	Services   map[int]ServiceInfo // service detail by port, for open ports that carry it
	// Per-port service-attached detail for open ports (nil when none observed).
	Endpoints    map[int][]EndpointInfo
	Technologies map[int][]TechnologyInfo
	Certificates map[int]CertificateInfo
	Surprise     string // non-empty if the entity carries a Surprise
	Belief       Belief // attack-path belief (zero until a BeliefSystem scores it)
	// CauseEdgeTypes mirrors Host.CauseEdgeTypes (gibson#613).
	CauseEdgeTypes []string
	Attention      float64 // derived: belief.Juicy + surprise boost (ADR-0129/0106)
	MissionID      string  // the mission that discovered this host (gibson#1075); empty if none
	// EvidenceDigest fingerprints the evidence Belief was scored against
	// (belief.go). Belief is a first-class property of the node (gibson#272), so
	// the digest that gates its recompute travels with the node's snapshot
	// rather than staying internal to the Host component: a consumer — the
	// graph projection, a reviewer inspecting a frame — can then tell which
	// evidence a recorded Belief answers for without re-deriving it. Empty
	// until the first score request is made.
	EvidenceDigest string
}

// Snapshot returns the current hosts in deterministic order — the materialized
// state derived from the fold so far.
func (w *World) Snapshot() []HostSnapshot {
	// First collect entities carrying a Surprise (separate query; drains fully).
	surprised := map[ecs.Entity]string{}
	sq := ecs.NewFilter1[Surprise](w.ecs).Query()
	for sq.Next() {
		surprised[sq.Entity()] = sq.Get().Reason
	}

	var out []HostSnapshot
	q := ecs.NewFilter1[Host](w.ecs).Query()
	for q.Next() {
		h := q.Get()
		var open []int
		var svcs map[int]ServiceInfo
		var eps map[int][]EndpointInfo
		var techs map[int][]TechnologyInfo
		var certs map[int]CertificateInfo
		for _, p := range h.Ports {
			if p.Open {
				open = append(open, p.Number)
				if (p.Service != ServiceInfo{}) {
					if svcs == nil {
						svcs = map[int]ServiceInfo{}
					}
					svcs[p.Number] = p.Service
				}
				if len(p.Endpoints) > 0 {
					if eps == nil {
						eps = map[int][]EndpointInfo{}
					}
					eps[p.Number] = append([]EndpointInfo(nil), p.Endpoints...)
				}
				if len(p.Technologies) > 0 {
					if techs == nil {
						techs = map[int][]TechnologyInfo{}
					}
					techs[p.Number] = append([]TechnologyInfo(nil), p.Technologies...)
				}
				if (p.Certificate != CertificateInfo{}) {
					if certs == nil {
						certs = map[int]CertificateInfo{}
					}
					certs[p.Number] = p.Certificate
				}
			}
		}
		sort.Ints(open)
		out = append(out, HostSnapshot{
			ID:             h.ID,
			ScopeID:        h.ScopeID,
			Address:        h.Address,
			SSHHostKey:     h.SSHHostKey,
			CloudID:        h.CloudID,
			OpenPorts:      open,
			Services:       svcs,
			Endpoints:      eps,
			Technologies:   techs,
			Certificates:   certs,
			Surprise:       surprised[q.Entity()],
			Belief:         h.Belief,
			CauseEdgeTypes: append([]string(nil), h.CauseEdgeTypes...),
			Attention:      attentionScore(h.Belief.Juicy, h.Belief.Exploitable, surprised[q.Entity()] != ""),
			MissionID:      h.MissionID,
			EvidenceDigest: h.EvidenceDigest,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].SSHHostKey < out[j].SSHHostKey
	})
	return out
}

// Event is a domain event on the Timeline. Acting = emitting an event (the write).
type Event interface{ Kind() string }

// HostObserved records that a host was seen at (ScopeID, Address), optionally
// with strong identity signals, the set of ports observed open in this scan, and
// optional per-port service detail. Services is keyed by port number; a port may
// appear in OpenPorts without a Services entry (a bare open port) — service detail
// is enriched progressively across observations (ADR-0107).
type HostObserved struct {
	// MissionID links the sighting to the mission whose work produced it — the
	// mission-evidence edge (gibson#1075), carried from the ingest ContextInfo so a
	// mission-scoped slice surfaces the hosts that mission discovered. Empty when the
	// observation has no mission context (tenant-ambient).
	MissionID  string
	ScopeID    string
	Address    string
	SSHHostKey string
	CloudID    string
	OpenPorts  []int
	Services   map[int]ServiceInfo
	// Per-port service detail (keyed by port number; all optional).
	Endpoints    map[int][]EndpointInfo
	Technologies map[int][]TechnologyInfo
	Certificates map[int]CertificateInfo
}

func (HostObserved) Kind() string { return "host.observed" }

// Reduce folds one event into the World. It is the ONLY thing that mutates the
// World, and must be driven by a single goroutine (the engine tick).
func Reduce(w *World, ev Event) {
	switch e := ev.(type) {
	case HostObserved:
		applyHostObserved(w, e)
	case DomainObserved:
		applyDomainObserved(w, e)
	case SubdomainObserved:
		applySubdomainObserved(w, e)
	case CredentialObserved:
		applyCredentialObserved(w, e)
	case AccountObserved:
		applyAccountObserved(w, e)
	case WorkDispatched:
		applyWorkDispatched(w, e)
	case WorkRetried:
		applyWorkRetried(w, e)
	case WorkCompleted:
		applyWorkCompleted(w, e)
	case ConditionResolved:
		applyConditionResolved(w, e)
	case DecisionRequested:
		applyDecisionRequested(w, e)
	case DecisionCompleted:
		applyDecisionCompleted(w, e)
	case TokenUsed:
		applyTokenUsed(w, e)
	case MissionCreated:
		applyMissionCreated(w, e)
	case MissionStarted:
		applyMissionStarted(w, e)
	case MissionProjected:
		applyMissionProjected(w, e)
	case MissionPauseRequested:
		applyMissionPauseRequested(w, e)
	case MissionResumed:
		applyMissionResumed(w, e)
	case MissionDone:
		applyMissionDone(w, e)
	case MissionRewound:
		applyMissionRewound(w, e)
	case BeliefScoreRequested:
		applyBeliefScoreRequested(w, e)
	case BeliefScored:
		applyBeliefScored(w, e)
	case FindingRaised:
		applyFindingRaised(w, e)
	case LabelApplied:
		applyLabelApplied(w, e)
	case AgentRunObserved:
		applyAgentRunObserved(w, e)
	case HypothesisObserved:
		applyHypothesisObserved(w, e)
	case BetSettledTrue:
		applyBetSettledTrue(w, e)
	case BetSettledFalse:
		applyBetSettledFalse(w, e)
	case BetSettledByHITL:
		applyBetSettledByHITL(w, e)
	case DestructiveActionRequested:
		applyDestructiveActionRequested(w, e)
	case DestructiveActionDecided:
		applyDestructiveActionDecided(w, e)
	case LlmCallObserved:
		applyLlmCallObserved(w, e)
	case AgentToolCallObserved:
		applyAgentToolCallObserved(w, e)
	case FlightRecorderPolicySet:
		applyFlightRecorderPolicySet(w, e)
	case FlightRecorderRetentionSwept:
		applyFlightRecorderRetentionSwept(w, e)
	case ObservationRecorded:
		applyObservationRecorded(w, e)
	case EntityObserved:
		applyEntityObserved(w, e)
	case FindingStatusChanged:
		applyFindingStatusChanged(w, e)
	case ScanReconciled:
		applyScanReconciled(w, e)
	case VoIPlanRequested:
		applyVoIPlanRequested(w, e)
	case VoIPlanned:
		applyVoIPlanned(w, e)
	case EdgeOutcomeObserved:
		applyEdgeOutcomeObserved(w, e)
	case NodeBeliefSet:
		applyNodeBeliefSet(w, e)
	case MissionOriginated:
		applyMissionOriginated(w, e)
	case DomainPackEnabled:
		applyDomainPackEnabled(w, e)
	case DomainPackDisabled:
		applyDomainPackDisabled(w, e)
	case BetProofSubmittedForReview:
		applyBetProofSubmittedForReview(w, e)
	case OntologyExtensionProposed:
		applyOntologyExtensionProposed(w, e)
	case OntologyExtensionApproved:
		applyOntologyExtensionApproved(w, e)
	case OntologyExtensionRejected:
		applyOntologyExtensionRejected(w, e)
	}
}

// Timeline is the per-tenant append-only event log — the system of record.
type Timeline struct{ events []Event }

// Append adds an event to the end of the log.
func (t *Timeline) Append(e Event) { t.events = append(t.events, e) }

// Events returns the ordered events.
func (t *Timeline) Events() []Event { return t.events }

// Len is the number of events recorded.
func (t *Timeline) Len() int { return len(t.events) }

// Replay rebuilds a World by folding the whole Timeline. World == fold(Timeline).
func Replay(tenant string, t *Timeline) *World {
	w := NewWorld(tenant)
	for _, ev := range t.Events() {
		Reduce(w, ev)
	}
	return w
}
