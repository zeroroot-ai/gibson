package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// Domain is a registrable domain entity. Identity is (ScopeID, Name) — ADR-0002
// scope-relative. Placeholder shape; sdk#340 will codegen from taxonomy/v1.
type Domain struct {
	ID      uint64
	ScopeID string
	Name    string
}

// Subdomain is an FQDN entity. Identity is (ScopeID, FQDN). DomainName (its parent
// registrable domain) and Addresses (the host coordinates it resolves to) are
// enriched progressively across observations.
type Subdomain struct {
	ID         uint64
	ScopeID    string
	FQDN       string
	DomainName string
	Addresses  []string
}

// DomainObserved records that a domain was seen in a scope.
type DomainObserved struct {
	ScopeID string
	Name    string
}

func (DomainObserved) Kind() string { return "domain.observed" }

// SubdomainObserved records an FQDN, optionally its parent domain and the
// addresses it resolves to (each a host coordinate within the same scope).
type SubdomainObserved struct {
	ScopeID   string
	FQDN      string
	Domain    string
	Addresses []string
}

func (SubdomainObserved) Kind() string { return "subdomain.observed" }

// applyDomainObserved resolves a domain to an existing entity within its scope
// (by name) or creates one — scope-relative identity (ADR-0002).
func applyDomainObserved(w *World, e DomainObserved) {
	q := ecs.NewFilter1[Domain](w.ecs).Query()
	for q.Next() {
		d := q.Get()
		if d.ScopeID == e.ScopeID && d.Name == e.Name {
			q.Close()
			return // already known; nothing volatile to update
		}
	}
	w.domains.NewEntity(&Domain{ID: w.newDomainID(), ScopeID: e.ScopeID, Name: e.Name})
}

// applySubdomainObserved resolves a subdomain by (scope, fqdn) or creates one,
// then enriches its parent domain and resolved addresses (union, never shrinks —
// ADR-0002 associations are time-bounded/kept).
func applySubdomainObserved(w *World, e SubdomainObserved) {
	q := ecs.NewFilter1[Subdomain](w.ecs).Query()
	var ent ecs.Entity
	found := false
	for q.Next() {
		s := q.Get()
		if s.ScopeID == e.ScopeID && s.FQDN == e.FQDN {
			ent, found = q.Entity(), true
			q.Close()
			break
		}
	}
	if !found {
		s := &Subdomain{ID: w.newSubdomainID(), ScopeID: e.ScopeID, FQDN: e.FQDN, DomainName: e.Domain}
		s.Addresses = unionAddresses(nil, e.Addresses)
		w.subdomains.NewEntity(s)
		return
	}
	s := w.subdomains.Get(ent)
	if s.DomainName == "" {
		s.DomainName = e.Domain
	}
	s.Addresses = unionAddresses(s.Addresses, e.Addresses)
}

// unionAddresses returns the sorted union of existing and observed addresses.
func unionAddresses(existing, observed []string) []string {
	set := make(map[string]struct{}, len(existing)+len(observed))
	for _, a := range existing {
		set[a] = struct{}{}
	}
	for _, a := range observed {
		if a != "" {
			set[a] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// DomainSnapshot is a stable, comparable view of a Domain.
type DomainSnapshot struct {
	ID      uint64
	ScopeID string
	Name    string
}

// DomainSnapshot returns domains in deterministic (scope, name) order.
func (w *World) DomainSnapshot() []DomainSnapshot {
	var out []DomainSnapshot
	q := ecs.NewFilter1[Domain](w.ecs).Query()
	for q.Next() {
		d := q.Get()
		out = append(out, DomainSnapshot{ID: d.ID, ScopeID: d.ScopeID, Name: d.Name})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// SubdomainSnapshot is a stable, comparable view of a Subdomain.
type SubdomainSnapshot struct {
	ID         uint64
	ScopeID    string
	FQDN       string
	DomainName string
	Addresses  []string
}

// SubdomainSnapshot returns subdomains in deterministic (scope, fqdn) order.
func (w *World) SubdomainSnapshot() []SubdomainSnapshot {
	var out []SubdomainSnapshot
	q := ecs.NewFilter1[Subdomain](w.ecs).Query()
	for q.Next() {
		s := q.Get()
		out = append(out, SubdomainSnapshot{
			ID: s.ID, ScopeID: s.ScopeID, FQDN: s.FQDN, DomainName: s.DomainName,
			Addresses: append([]string(nil), s.Addresses...),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].FQDN < out[j].FQDN
	})
	return out
}
