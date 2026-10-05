// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"sort"
	"strconv"

	"github.com/mlange-42/ark/ecs"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// belief_infra_graph.go builds the infra graph of a World: the input of
// DeriveAttackGraph (ADR-0129). The graph holds one node for each typed thing
// of the World and one edge for each relationship between two of them. These
// are the relationships that the graph projector writes (ADR-0107), read from
// the World and not from Neo4j: the World is the source of truth.
//
// The infra graph makes no belief decision. DeriveAttackGraph keeps the nodes
// whose kind the belief schema marks as belief-bearing and the edges whose
// type the schema marks as an enablement edge. So a new belief-bearing kind
// or a new enablement edge type needs a schema change only, not a change here.

// Relationship types of the World, as the Taxonomy names them.
const (
	infraEdgeHasPort      = "HAS_PORT"
	infraEdgeRunsService  = "RUNS_SERVICE"
	infraEdgeResolvesTo   = "RESOLVES_TO"
	infraEdgeHasSubdomain = "HAS_SUBDOMAIN"
	infraEdgeAffects      = "AFFECTS"
	infraEdgeDelegatedTo  = "DELEGATED_TO"
	infraEdgeIssued       = "ISSUED"

	infraKindHost = "Host"
)

// InfraNodeID is the InfraNode.ID of the World thing with this Taxonomy label
// and key. A Host keeps the plain id that HostNodeID gives, because
// WorldBeliefSubstrate reads and writes a Host by that id. Each other label
// puts the label in front of the key, so two kinds cannot share an id.
//
// The key of a first-class thing is its stable World id, the value that the
// graph projector stores as brain_id. So an entity edge that names a Host by
// (label, key) reaches the node of that Host.
func InfraNodeID(label, key string) string {
	if label == infraKindHost {
		return key
	}
	return label + "/" + key
}

// coordinate is the (scope, address) or (scope, name) identity of a thing.
type coordinate struct{ scope, name string }

// infraBuilder collects the nodes and the edges of one infra graph.
type infraBuilder struct {
	kinds  map[string]string // node id -> kind
	edges  []InfraEdge
	hostAt map[coordinate]string // (scope, address) -> Host node id
}

func (b *infraBuilder) link(edgeType, from, to string) {
	b.edges = append(b.edges, InfraEdge{Type: edgeType, From: from, To: to})
}

// addHosts adds each Host with its open ports and their services.
func (b *infraBuilder) addHosts(w *World) {
	q := ecs.NewFilter1[Host](w.ecs).Query()
	for q.Next() {
		h := q.Get()
		id := HostNodeID(h.ID)
		b.kinds[id] = infraKindHost
		b.hostAt[coordinate{h.ScopeID, h.Address}] = id
		for _, p := range h.Ports {
			if !p.Open {
				continue
			}
			port := InfraNodeID("Port", id+"/"+strconv.Itoa(p.Number))
			b.kinds[port] = "Port"
			b.link(infraEdgeHasPort, id, port)
			if p.Service.Name == "" {
				continue
			}
			service := InfraNodeID("Service", id+"/"+strconv.Itoa(p.Number))
			b.kinds[service] = "Service"
			b.link(infraEdgeRunsService, port, service)
		}
	}
}

// addNames adds each Domain and Subdomain, and the hosts that a subdomain
// resolves to.
func (b *infraBuilder) addNames(w *World) {
	domainAt := map[coordinate]string{}
	dq := ecs.NewFilter1[Domain](w.ecs).Query()
	for dq.Next() {
		d := dq.Get()
		id := InfraNodeID("Domain", strconv.FormatUint(d.ID, 10))
		b.kinds[id] = "Domain"
		domainAt[coordinate{d.ScopeID, d.Name}] = id
	}

	sq := ecs.NewFilter1[Subdomain](w.ecs).Query()
	for sq.Next() {
		s := sq.Get()
		id := InfraNodeID("Subdomain", strconv.FormatUint(s.ID, 10))
		b.kinds[id] = "Subdomain"
		if domain, ok := domainAt[coordinate{s.ScopeID, s.DomainName}]; ok {
			b.link(infraEdgeHasSubdomain, domain, id)
		}
		for _, addr := range s.Addresses {
			if host, ok := b.hostAt[coordinate{s.ScopeID, addr}]; ok {
				b.link(infraEdgeResolvesTo, id, host)
			}
		}
	}
}

// addFindings adds each Finding and the host that it affects.
func (b *infraBuilder) addFindings(w *World) {
	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		f := q.Get()
		id := InfraNodeID("Finding", f.ID)
		b.kinds[id] = "Finding"
		if host, ok := b.hostAt[coordinate{f.ScopeID, f.Address}]; ok {
			b.link(infraEdgeAffects, id, host)
		}
	}
}

// addProvenance adds each agent run and LLM call, with the delegation and the
// issue edges.
func (b *infraBuilder) addProvenance(w *World) {
	rq := ecs.NewFilter1[AgentRun](w.ecs).Query()
	for rq.Next() {
		r := rq.Get()
		id := InfraNodeID("AgentRun", r.RunID)
		b.kinds[id] = "AgentRun"
		if r.ParentRunID != "" {
			b.link(infraEdgeDelegatedTo, InfraNodeID("AgentRun", r.ParentRunID), id)
		}
	}

	cq := ecs.NewFilter1[LlmCall](w.ecs).Query()
	for cq.Next() {
		c := cq.Get()
		id := InfraNodeID("LlmCall", c.CallID)
		b.kinds[id] = "LlmCall"
		if c.RunID != "" {
			b.link(infraEdgeIssued, InfraNodeID("AgentRun", c.RunID), id)
		}
	}
}

// addEntities adds each typed lifecycle entity and its edges. An entity with
// the label Host adds edges only: see infraGraph.
func (b *infraBuilder) addEntities(w *World) {
	q := ecs.NewFilter1[Entity](w.ecs).Query()
	for q.Next() {
		e := q.Get()
		id := InfraNodeID(e.Label, e.Key)
		if e.Label != infraKindHost {
			b.kinds[id] = e.Label
		}
		for _, edge := range e.Edges {
			b.link(edge.Type, id, InfraNodeID(edge.TargetLabel, edge.TargetKey))
		}
	}
}

// infraGraph returns the infra graph of the World, in a deterministic order:
// the nodes by id, the edges by (From, To, Type). The caller holds the lock.
//
// A Host node exists only for a Host that the World holds. An entity with the
// label Host adds edges to that node and never a second node: the belief
// substrate has no state for a host that the World did not observe.
func (w *World) infraGraph() ([]InfraNode, []InfraEdge) {
	b := &infraBuilder{kinds: map[string]string{}, hostAt: map[coordinate]string{}}
	b.addHosts(w) // first: the later steps look a host up by its coordinate
	b.addNames(w)
	b.addFindings(w)
	b.addProvenance(w)
	b.addEntities(w)

	nodes := make([]InfraNode, 0, len(b.kinds))
	for id, kind := range b.kinds {
		nodes = append(nodes, InfraNode{ID: id, Kind: kind})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	edges := b.edges
	sort.Slice(edges, func(i, j int) bool {
		x, y := edges[i], edges[j]
		if x.From != y.From {
			return x.From < y.From
		}
		if x.To != y.To {
			return x.To < y.To
		}
		return x.Type < y.Type
	})
	return nodes, edges
}

// InfraGraph returns the infra graph of the tenant World: the nodes and the
// relationships that DeriveAttackGraph takes. Read-locked, so it is safe
// beside the tick.
func (e *Engine) InfraGraph() ([]InfraNode, []InfraEdge) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.infraGraph()
}

// LiveAttackGraph derives the acyclic attack graph of the tenant World
// (ADR-0129): LiveEnablementGraph with its cycles cut. The planner uses it. It
// is the one way that the planner gets an attack graph, so no path can leave
// the relationships of the World out (gibson#697).
func LiveAttackGraph(eng *Engine, hosts []HostSnapshot, registry *ontology.BeliefSchemaRegistry) AttackGraph {
	return BreakCycles(LiveEnablementGraph(eng, hosts, registry))
}

// LiveEnablementGraph is the uncut enablement graph of the tenant World. The
// belief engine slices it and breaks the cycles of each slice (gibson#700).
//
// hosts bounds the Host nodes of the graph: the belief engine passes each host
// of the World, and the planner passes the ambient slice of the mission. An
// edge to a host outside the bound has no endpoint in the graph, and
// EnablementGraph drops it.
func LiveEnablementGraph(eng *Engine, hosts []HostSnapshot, registry *ontology.BeliefSchemaRegistry) AttackGraph {
	nodes, edges := eng.InfraGraph()

	inBound := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		inBound[HostNodeID(h.ID)] = struct{}{}
	}
	bounded := make([]InfraNode, 0, len(nodes))
	for _, n := range nodes {
		if n.Kind == infraKindHost {
			if _, ok := inBound[n.ID]; !ok {
				continue
			}
		}
		bounded = append(bounded, n)
	}
	return EnablementGraph(bounded, edges, registry)
}
