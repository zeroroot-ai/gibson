// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
)

// discoveryEvents translates a DiscoveryResult into the brain Timeline events
// that carry the same information, in a deterministic order.
//
// The translation is total in one direction only: every entity the global
// Taxonomy covers becomes an event, and everything else is counted as skipped
// rather than invented into the World. Out-of-taxonomy shapes are meant to land
// as Observations (ADR-0012), which does not exist yet — gibson#1258 builds it.
// Counting is the honest interim: the caller logs a non-zero skip count, so
// dropped shapes are visible instead of silent.
//
// Topology is flat on the wire (parallel lists joined by agent-generated ids)
// and nested in the World (ports, services, endpoints, technologies and
// certificates are all sub-state of a Host). Reassembling it here is the whole
// job: resolve each child to its host and port, then emit one HostObserved per
// host carrying the lot.
func discoveryEvents(execCtx ExecContext, d *graphragpb.DiscoveryResult) (events []brain.Event, skipped int) {
	if d == nil {
		return nil, 0
	}
	scope := execCtx.MissionID

	portOf := indexPortRefs(d)
	details, hostSkipped := hostDetails(d, portOf)
	skipped += hostSkipped

	hostEvents, addressByHostID, addrSkipped := hostObservedEvents(execCtx, d, details)
	skipped += addrSkipped
	events = append(events, hostEvents...)

	domainEvents, domainNameByID, domainSkipped := domainObservedEvents(scope, d)
	skipped += domainSkipped
	events = append(events, domainEvents...)

	subdomainEvents, subdomainSkipped := subdomainObservedEvents(scope, d, domainNameByID)
	skipped += subdomainSkipped
	events = append(events, subdomainEvents...)

	findingEvents, findingSkipped := findingRaisedEvents(execCtx, d, addressByHostID)
	skipped += findingSkipped
	events = append(events, findingEvents...)

	entityEvents, entitySkipped := entityObservedEvents(execCtx, d)
	skipped += entitySkipped
	events = append(events, entityEvents...)

	// Evidence has no World vocabulary yet. It is the Observations case
	// (ADR-0012) that gibson#1258 builds.
	skipped += len(d.Evidence)

	return events, skipped
}

// entityObservedEvents translates CustomNodes and ExplicitRelationships into
// EntityObserved events (gibson#1656). The Taxonomy is the gate: a custom node
// whose type is an admitted label becomes a typed entity keyed by its
// identifying properties; one whose type is not admitted is counted as skipped
// rather than invented into the World. The same rule applies to the parent
// link a custom node carries and to every explicit relationship: both ends and
// the relationship type must be admitted, or the edge is skipped.
//
// The label that reaches the World is the Taxonomy's own string, never the
// wire's: ClassifyNode returns a registry member or the Observation fallback,
// and only the former is used here.
func entityObservedEvents(execCtx ExecContext, d *graphragpb.DiscoveryResult) (events []brain.Event, skipped int) {
	scope := execCtx.MissionID
	for _, n := range d.CustomNodes {
		if n == nil {
			skipped++
			continue
		}
		sighting := EntitySighting{
			Label:        n.NodeType,
			IDProperties: n.IdProperties,
			Properties:   n.Properties,
		}
		// A CustomNode carries at most one edge, to its parent.
		if n.GetParentType() != "" || n.GetRelationshipType() != "" {
			sighting.Edges = append(sighting.Edges, EntitySightingEdge{
				Type:               n.GetRelationshipType(),
				TargetLabel:        n.GetParentType(),
				TargetIDProperties: n.ParentId,
			})
		}
		ev, edgeSkipped, ok := EntityObservedFromSighting(sighting, scope, execCtx.MissionID)
		skipped += edgeSkipped
		if !ok {
			skipped++
			continue
		}
		events = append(events, ev)
	}
	for _, r := range d.ExplicitRelationships {
		if r == nil {
			skipped++
			continue
		}
		fromLabel, fromOK := admittedLabel(r.FromType)
		toLabel, toOK := admittedLabel(r.ToType)
		relType, relOK := admittedRelationship(r.RelationshipType)
		fromKey, toKey := EntityKey(r.FromId), EntityKey(r.ToId)
		if !fromOK || !toOK || !relOK || fromKey == "" || toKey == "" {
			skipped++
			continue
		}
		events = append(events, brain.EntityObserved{
			Label:     fromLabel,
			Key:       fromKey,
			ScopeID:   scope,
			MissionID: execCtx.MissionID,
			Edges: []brain.EntityEdge{{
				Type: relType, TargetLabel: toLabel, TargetKey: toKey,
			}},
		})
	}
	return events, skipped
}

// admittedLabel puts a wire node type to the global Taxonomy and returns the
// Taxonomy's label when admitted.
func admittedLabel(nodeType string) (string, bool) {
	d := taxonomy.Global.ClassifyNode(nodeType)
	if !d.InTaxonomy {
		return "", false
	}
	return d.Label, true
}

// admittedRelationship puts a wire relationship type to the global Taxonomy.
func admittedRelationship(relType string) (string, bool) {
	d := taxonomy.Global.ClassifyRelationship(relType)
	if !d.InTaxonomy {
		return "", false
	}
	return d.Label, true
}

// EntityKey derives the stable key of a typed entity from its identifying
// properties. One identifying property is the key verbatim, so a Vulnerability
// identified by {id: CVE-2025-1234} has the key CVE-2025-1234 and a Finding's
// vulnerability id matches it. Several properties are joined in sorted
// key=value form, so the key is independent of map order. No properties, no
// key: the entity cannot be merged idempotently and is skipped.
func EntityKey(idProps map[string]string) string {
	switch len(idProps) {
	case 0:
		return ""
	case 1:
		for _, v := range idProps {
			return strings.TrimSpace(v)
		}
	}
	keys := make([]string, 0, len(idProps))
	for k := range idProps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strings.TrimSpace(idProps[k]))
	}
	return strings.Join(parts, "|")
}

func cloneProps(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// firstVulnerabilityID picks the shared weakness identity out of a finding's
// cve_ids field, which carries one or more ids separated by commas, spaces or
// semicolons. The first one is the identity; the rest stay in the description.
func firstVulnerabilityID(cveIDs string) string {
	fields := strings.FieldsFunc(cveIDs, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// portRef is the (host, port number) coordinate any port/service/endpoint id
// resolves to.
type portRef struct {
	hostID string
	number int
}

// indexPortRefs resolves every port, service and endpoint id to the port it
// hangs off, so a Technology or Certificate naming any of the three attaches to
// the right port of the right host.
func indexPortRefs(d *graphragpb.DiscoveryResult) map[string]portRef {
	portOf := make(map[string]portRef, len(d.Ports)+len(d.Services)+len(d.Endpoints))
	for _, p := range d.Ports {
		if p == nil || p.HostId == "" {
			continue
		}
		portOf[p.GetId()] = portRef{hostID: p.HostId, number: int(p.Number)}
	}
	for _, s := range d.Services {
		if s == nil {
			continue
		}
		if ref, ok := portOf[s.PortId]; ok {
			portOf[s.GetId()] = ref
		}
	}
	for _, e := range d.Endpoints {
		if e == nil {
			continue
		}
		if ref, ok := portOf[e.ServiceId]; ok {
			portOf[e.GetId()] = ref
		}
	}
	return portOf
}

// hostDetail is the nested per-host sub-state the World models: ports, and the
// services / endpoints / technologies / certificates hanging off each port.
type hostDetail struct {
	openPorts    []int
	services     map[int]brain.ServiceInfo
	endpoints    map[int][]brain.EndpointInfo
	technologies map[int][]brain.TechnologyInfo
	certificates map[int]brain.CertificateInfo
}

// hostDetails reassembles the wire format's flat parallel lists into the
// World's nested host sub-state, counting everything it cannot place.
//
// Counting rather than inventing is the contract: a dangling reference names a
// port or host this payload does not contain, and materialising the parent it
// claims would put a shape in the graph no agent ever reported.
func hostDetails(d *graphragpb.DiscoveryResult, portOf map[string]portRef) (details map[string]*hostDetail, skipped int) {
	servicesByPortID := make(map[string]*graphragpb.Service, len(d.Services))
	for _, s := range d.Services {
		if s != nil {
			servicesByPortID[s.PortId] = s
		}
	}
	endpointsByServiceID := make(map[string][]*graphragpb.Endpoint, len(d.Endpoints))
	for _, e := range d.Endpoints {
		if e != nil {
			endpointsByServiceID[e.ServiceId] = append(endpointsByServiceID[e.ServiceId], e)
		}
	}

	details = make(map[string]*hostDetail, len(d.Hosts))
	detailFor := func(hostID string) *hostDetail {
		hd, ok := details[hostID]
		if !ok {
			hd = &hostDetail{}
			details[hostID] = hd
		}
		return hd
	}

	for _, p := range d.Ports {
		if p == nil || p.HostId == "" {
			skipped++
			continue
		}
		hd := detailFor(p.HostId)
		num := int(p.Number)
		hd.openPorts = append(hd.openPorts, num)
		if svc, ok := serviceInfoFor(p, servicesByPortID, endpointsByServiceID, hd, num); ok {
			if hd.services == nil {
				hd.services = map[int]brain.ServiceInfo{}
			}
			hd.services[num] = svc
		}
	}

	// A service or endpoint whose parent id names nothing in this payload is a
	// dangling reference.
	for _, s := range d.Services {
		if _, ok := portOf[s.GetPortId()]; s == nil || !ok {
			skipped++
		}
	}
	for _, e := range d.Endpoints {
		if _, ok := portOf[e.GetServiceId()]; e == nil || !ok {
			skipped++
		}
	}

	skipped += attachTechnologies(d, portOf, detailFor)
	skipped += attachCertificates(d, portOf, detailFor)

	return details, skipped
}

// serviceInfoFor builds the ServiceInfo for one port and records that service's
// endpoints on the host detail. ok is false when the port carries no service
// information at all.
func serviceInfoFor(
	p *graphragpb.Port,
	servicesByPortID map[string]*graphragpb.Service,
	endpointsByServiceID map[string][]*graphragpb.Endpoint,
	hd *hostDetail,
	num int,
) (brain.ServiceInfo, bool) {
	svc := brain.ServiceInfo{Protocol: p.Protocol}
	if s := servicesByPortID[p.GetId()]; s != nil {
		svc.Name = s.Name
		svc.Product = s.GetProduct()
		svc.Version = s.GetVersion()
		for _, e := range endpointsByServiceID[s.GetId()] {
			if hd.endpoints == nil {
				hd.endpoints = map[int][]brain.EndpointInfo{}
			}
			hd.endpoints[num] = append(hd.endpoints[num], brain.EndpointInfo{
				Path:   e.Url,
				Status: int(e.GetStatusCode()),
			})
		}
	}
	return svc, svc != (brain.ServiceInfo{})
}

// attachTechnologies records each technology against the port it names,
// counting host-level or unparented ones: the World models technology as port
// sub-state, so there is nowhere else for them to go.
func attachTechnologies(d *graphragpb.DiscoveryResult, portOf map[string]portRef, detailFor func(string) *hostDetail) int {
	var skipped int
	for _, t := range d.Technologies {
		if t == nil {
			skipped++
			continue
		}
		ref, ok := portOf[t.GetParentId()]
		if !ok {
			skipped++
			continue
		}
		hd := detailFor(ref.hostID)
		if hd.technologies == nil {
			hd.technologies = map[int][]brain.TechnologyInfo{}
		}
		hd.technologies[ref.number] = append(hd.technologies[ref.number], brain.TechnologyInfo{
			Name:    t.Name,
			Version: t.GetVersion(),
		})
	}
	return skipped
}

// attachCertificates records each certificate against the port it names.
func attachCertificates(d *graphragpb.DiscoveryResult, portOf map[string]portRef, detailFor func(string) *hostDetail) int {
	var skipped int
	for _, c := range d.Certificates {
		if c == nil {
			skipped++
			continue
		}
		ref, ok := portOf[c.GetParentId()]
		if !ok {
			skipped++
			continue
		}
		hd := detailFor(ref.hostID)
		if hd.certificates == nil {
			hd.certificates = map[int]brain.CertificateInfo{}
		}
		notAfter := ""
		if c.NotAfter != nil {
			notAfter = strconv.FormatInt(c.GetNotAfter(), 10)
		}
		hd.certificates[ref.number] = brain.CertificateInfo{
			Fingerprint: c.GetFingerprintSha256(),
			Subject:     c.GetSubject(),
			Issuer:      c.GetIssuer(),
			NotAfter:    notAfter,
		}
	}
	return skipped
}

// hostObservedEvents emits one HostObserved per host carrying its whole
// sub-state, and returns the id→address index a Finding parented on a host
// needs: the World records a finding's host coordinate, not an agent-generated
// uuid.
func hostObservedEvents(
	execCtx ExecContext,
	d *graphragpb.DiscoveryResult,
	details map[string]*hostDetail,
) (events []brain.Event, addressByHostID map[string]string, skipped int) {
	addressByHostID = make(map[string]string, len(d.Hosts))
	for _, h := range d.Hosts {
		if h == nil || h.Ip == "" {
			// Address is half the host's identity coordinate (ADR-0002); without
			// it the sighting cannot be resolved to an entity.
			skipped++
			continue
		}
		addressByHostID[h.GetId()] = h.Ip

		ev := brain.HostObserved{
			MissionID: execCtx.MissionID,
			ScopeID:   execCtx.MissionID,
			Address:   h.Ip,
		}
		if hd := details[h.GetId()]; hd != nil {
			ev.OpenPorts = hd.openPorts
			ev.Services = hd.services
			ev.Endpoints = hd.endpoints
			ev.Technologies = hd.technologies
			ev.Certificates = hd.certificates
		}
		events = append(events, ev)
	}
	return events, addressByHostID, skipped
}

// domainObservedEvents emits one DomainObserved per named domain and returns
// the id→name index subdomains resolve their parent through.
func domainObservedEvents(scope string, d *graphragpb.DiscoveryResult) (events []brain.Event, domainNameByID map[string]string, skipped int) {
	domainNameByID = make(map[string]string, len(d.Domains))
	for _, dom := range d.Domains {
		if dom == nil || dom.Name == "" {
			skipped++
			continue
		}
		domainNameByID[dom.GetId()] = dom.Name
		events = append(events, brain.DomainObserved{ScopeID: scope, Name: dom.Name})
	}
	return events, domainNameByID, skipped
}

// subdomainObservedEvents emits one SubdomainObserved per subdomain that has a
// usable FQDN.
func subdomainObservedEvents(scope string, d *graphragpb.DiscoveryResult, domainNameByID map[string]string) (events []brain.Event, skipped int) {
	for _, sd := range d.Subdomains {
		if sd == nil {
			skipped++
			continue
		}
		fqdn := sd.GetFullName()
		if fqdn == "" {
			fqdn = sd.Name
		}
		if fqdn == "" {
			skipped++
			continue
		}
		events = append(events, brain.SubdomainObserved{
			ScopeID: scope,
			FQDN:    fqdn,
			Domain:  domainNameByID[sd.DomainId],
		})
	}
	return events, skipped
}

// findingRaisedEvents emits one FindingRaised per titled finding, carrying the
// address of the host it names.
func findingRaisedEvents(execCtx ExecContext, d *graphragpb.DiscoveryResult, addressByHostID map[string]string) (events []brain.Event, skipped int) {
	for _, f := range d.Findings {
		if f == nil || f.Title == "" {
			skipped++
			continue
		}
		events = append(events, brain.FindingRaised{
			ID:              findingID(execCtx.MissionID, f),
			Title:           f.Title,
			Description:     f.GetDescription(),
			Severity:        f.Severity,
			ScopeID:         execCtx.MissionID,
			Address:         addressByHostID[f.GetParentId()],
			MissionID:       execCtx.MissionID,
			Status:          brain.FindingStatusOpen,
			VulnerabilityID: firstVulnerabilityID(f.GetCveIds()),
		})
	}
	return events, skipped
}

// findingID returns the World identity for a discovered finding. The reducer
// dedupes findings by id, so this has to be stable across re-deliveries of the
// same discovery: an agent-supplied id when there is one, and otherwise a hash
// of the finding's content within its scope. A random id would turn every retry
// into a new finding.
func findingID(scope string, f *graphragpb.Finding) string {
	if id := f.GetId(); id != "" {
		return id
	}
	h := sha256.New()
	for _, part := range []string{scope, f.Title, f.Severity, f.GetDescription(), f.GetCategory()} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "discovery-" + hex.EncodeToString(h.Sum(nil)[:16])
}

// EntitySighting is one typed application-lifecycle entity somebody reported,
// in a shape neither of its two callers owns.
//
// A tool reports one as a DiscoveryResult CustomNode; an agent reports one as a
// LifecycleEntityObservation on the Observe callback (sdk#537). Both mean the
// same thing, so both translate through EntityObservedFromSighting rather than
// growing a second mapping that can disagree with the first (ADR-0027) — which
// is the defect class gibson#1674 fixed on the identity side.
type EntitySighting struct {
	// Label is the Taxonomy node label the reporter named, unvalidated.
	Label string
	// IDProperties identify the node. A single entry is the natural key; the
	// composite case is decided by EntityKey.
	IDProperties map[string]string
	// Properties are the non-identity properties to enrich the node with.
	Properties map[string]string
	Edges      []EntitySightingEdge
}

// EntitySightingEdge is one outgoing relationship to another typed entity.
type EntitySightingEdge struct {
	Type               string
	TargetLabel        string
	TargetIDProperties map[string]string
}

// EntityObservedFromSighting translates a sighting into the EntityObserved event
// the projector already consumes.
//
// It returns ok=false when the label is outside the Taxonomy or the sighting
// carries no usable key — the reporter named something the graph cannot address,
// and the caller lands it as an untyped Observation instead of dropping it.
// skipped counts edges that were individually inadmissible; the entity itself
// still lands, because losing a node over one bad edge would lose more than it
// protects.
func EntityObservedFromSighting(s EntitySighting, scopeID, missionID string) (ev brain.EntityObserved, skipped int, ok bool) {
	label, labelOK := admittedLabel(s.Label)
	key := EntityKey(s.IDProperties)
	if !labelOK || key == "" {
		return brain.EntityObserved{}, 0, false
	}

	ev = brain.EntityObserved{
		Label:     label,
		Key:       key,
		ScopeID:   scopeID,
		MissionID: missionID,
		Props:     cloneProps(s.Properties),
	}
	for _, e := range s.Edges {
		targetLabel, targetOK := admittedLabel(e.TargetLabel)
		relType, relOK := admittedRelationship(e.Type)
		targetKey := EntityKey(e.TargetIDProperties)
		if !targetOK || !relOK || targetKey == "" {
			skipped++
			continue
		}
		ev.Edges = append(ev.Edges, brain.EntityEdge{
			Type: relType, TargetLabel: targetLabel, TargetKey: targetKey,
		})
	}
	return ev, skipped, true
}
