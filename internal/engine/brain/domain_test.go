package brain

import (
	"reflect"
	"testing"
)

// TestDomainSubdomain_FoldDedupReplay proves domains/subdomains fold with
// scope-relative identity (ADR-0002), subdomains enrich their parent + resolved
// addresses progressively (union, never shrinks), and the World survives replay.
func TestDomainSubdomain_FoldDedupReplay(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(DomainObserved{ScopeID: "s", Name: "example.com"})
	apply(DomainObserved{ScopeID: "s", Name: "example.com"})  // dup: no new entity
	apply(DomainObserved{ScopeID: "s2", Name: "example.com"}) // different scope: distinct

	// Subdomain seen twice: parent + addresses accrete across observations.
	apply(SubdomainObserved{ScopeID: "s", FQDN: "api.example.com", Addresses: []string{"10.0.0.5"}})
	apply(SubdomainObserved{ScopeID: "s", FQDN: "api.example.com", Domain: "example.com", Addresses: []string{"10.0.0.6"}})

	domains := w.DomainSnapshot()
	wantDomains := []DomainSnapshot{
		{ID: 1, ScopeID: "s", Name: "example.com"},
		{ID: 2, ScopeID: "s2", Name: "example.com"},
	}
	if !reflect.DeepEqual(domains, wantDomains) {
		t.Fatalf("domains:\n got %+v\nwant %+v", domains, wantDomains)
	}

	subs := w.SubdomainSnapshot()
	wantSubs := []SubdomainSnapshot{
		{ID: 1, ScopeID: "s", FQDN: "api.example.com", DomainName: "example.com", Addresses: []string{"10.0.0.5", "10.0.0.6"}},
	}
	if !reflect.DeepEqual(subs, wantSubs) {
		t.Fatalf("subdomains:\n got %+v\nwant %+v", subs, wantSubs)
	}

	r := Replay("t", tl)
	if !reflect.DeepEqual(r.DomainSnapshot(), domains) || !reflect.DeepEqual(r.SubdomainSnapshot(), subs) {
		t.Fatal("replay diverged for domains/subdomains")
	}
}
