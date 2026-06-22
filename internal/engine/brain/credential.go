package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// Credential is a discovered-credential entity. Identity is (ScopeID, SecretHash)
// — the hash, never the raw secret (ADR-0002 scope-relative; ADR-0007).
type Credential struct {
	ID         uint64
	ScopeID    string
	SecretHash string
	Username   string
	Kind       string
}

// Account is a discovered account/principal entity. Identity is (ScopeID, Identifier).
type Account struct {
	ID         uint64
	ScopeID    string
	Identifier string
	Kind       string
}

// CredentialObserved records a discovered credential (identity: secret hash).
type CredentialObserved struct {
	ScopeID        string
	SecretHash     string
	Username       string
	CredentialKind string
}

func (CredentialObserved) Kind() string { return "credential.observed" }

// AccountObserved records a discovered account/principal.
type AccountObserved struct {
	ScopeID     string
	Identifier  string
	AccountKind string
}

func (AccountObserved) Kind() string { return "account.observed" }

// applyCredentialObserved resolves a credential by (scope, secret hash) or creates
// one, enriching username/kind progressively.
func applyCredentialObserved(w *World, e CredentialObserved) {
	q := ecs.NewFilter1[Credential](w.ecs).Query()
	var ent ecs.Entity
	found := false
	for q.Next() {
		c := q.Get()
		if c.ScopeID == e.ScopeID && c.SecretHash == e.SecretHash {
			ent, found = q.Entity(), true
			q.Close()
			break
		}
	}
	if !found {
		w.credentials.NewEntity(&Credential{
			ID: w.newCredentialID(), ScopeID: e.ScopeID, SecretHash: e.SecretHash,
			Username: e.Username, Kind: e.CredentialKind,
		})
		return
	}
	c := w.credentials.Get(ent)
	if c.Username == "" {
		c.Username = e.Username
	}
	if c.Kind == "" {
		c.Kind = e.CredentialKind
	}
}

// applyAccountObserved resolves an account by (scope, identifier) or creates one,
// enriching kind progressively.
func applyAccountObserved(w *World, e AccountObserved) {
	q := ecs.NewFilter1[Account](w.ecs).Query()
	var ent ecs.Entity
	found := false
	for q.Next() {
		a := q.Get()
		if a.ScopeID == e.ScopeID && a.Identifier == e.Identifier {
			ent, found = q.Entity(), true
			q.Close()
			break
		}
	}
	if !found {
		w.accounts.NewEntity(&Account{
			ID: w.newAccountID(), ScopeID: e.ScopeID, Identifier: e.Identifier, Kind: e.AccountKind,
		})
		return
	}
	a := w.accounts.Get(ent)
	if a.Kind == "" {
		a.Kind = e.AccountKind
	}
}

// CredentialSnapshot is a stable, comparable view of a Credential.
type CredentialSnapshot struct {
	ID         uint64
	ScopeID    string
	SecretHash string
	Username   string
	Kind       string
}

// CredentialSnapshot returns credentials in deterministic (scope, hash) order.
func (w *World) CredentialSnapshot() []CredentialSnapshot {
	var out []CredentialSnapshot
	q := ecs.NewFilter1[Credential](w.ecs).Query()
	for q.Next() {
		c := q.Get()
		out = append(out, CredentialSnapshot{
			ID: c.ID, ScopeID: c.ScopeID, SecretHash: c.SecretHash, Username: c.Username, Kind: c.Kind,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].SecretHash < out[j].SecretHash
	})
	return out
}

// AccountSnapshot is a stable, comparable view of an Account.
type AccountSnapshot struct {
	ID         uint64
	ScopeID    string
	Identifier string
	Kind       string
}

// AccountSnapshot returns accounts in deterministic (scope, identifier) order.
func (w *World) AccountSnapshot() []AccountSnapshot {
	var out []AccountSnapshot
	q := ecs.NewFilter1[Account](w.ecs).Query()
	for q.Next() {
		a := q.Get()
		out = append(out, AccountSnapshot{ID: a.ID, ScopeID: a.ScopeID, Identifier: a.Identifier, Kind: a.Kind})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].Identifier < out[j].Identifier
	})
	return out
}
