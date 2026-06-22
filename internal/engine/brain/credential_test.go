package brain

import (
	"reflect"
	"testing"
)

// TestCredentialAccount_FoldDedupReplay proves credentials/accounts fold with
// scope-relative identity (credential by secret hash, account by identifier),
// enrich progressively, and survive replay.
func TestCredentialAccount_FoldDedupReplay(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(CredentialObserved{ScopeID: "s", SecretHash: "ab12"})
	apply(CredentialObserved{ScopeID: "s", SecretHash: "ab12", Username: "root", CredentialKind: "ssh_key"}) // enrich
	apply(CredentialObserved{ScopeID: "s2", SecretHash: "ab12"})                                             // different scope: distinct
	apply(AccountObserved{ScopeID: "s", Identifier: "admin"})
	apply(AccountObserved{ScopeID: "s", Identifier: "admin", AccountKind: "local"}) // enrich; same identity

	creds := w.CredentialSnapshot()
	wantCreds := []CredentialSnapshot{
		{ID: 1, ScopeID: "s", SecretHash: "ab12", Username: "root", Kind: "ssh_key"},
		{ID: 2, ScopeID: "s2", SecretHash: "ab12"},
	}
	if !reflect.DeepEqual(creds, wantCreds) {
		t.Fatalf("credentials:\n got %+v\nwant %+v", creds, wantCreds)
	}

	accts := w.AccountSnapshot()
	wantAccts := []AccountSnapshot{{ID: 1, ScopeID: "s", Identifier: "admin", Kind: "local"}}
	if !reflect.DeepEqual(accts, wantAccts) {
		t.Fatalf("accounts:\n got %+v\nwant %+v", accts, wantAccts)
	}

	r := Replay("t", tl)
	if !reflect.DeepEqual(r.CredentialSnapshot(), creds) || !reflect.DeepEqual(r.AccountSnapshot(), accts) {
		t.Fatal("replay diverged for credentials/accounts")
	}
}
