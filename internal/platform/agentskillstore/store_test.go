// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentskillstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
)

// fakeSQL answers each statement from a table keyed by a fragment of the SQL.
// It checks the logic of the store. The migration and the statements agree is
// the part that only a real database can prove.
type fakeSQL struct {
	rows map[string][]any
	seen []string
}

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return fmt.Errorf("scan: %d destinations for %d values", len(dest), len(r.values))
	}
	for i, d := range dest {
		reflect.ValueOf(d).Elem().Set(reflect.ValueOf(r.values[i]))
	}
	return nil
}

func (f *fakeSQL) Exec(_ context.Context, sql string, _ ...any) (int64, error) {
	f.seen = append(f.seen, sql)
	return 1, nil
}

func (f *fakeSQL) QueryRow(_ context.Context, sql string, _ ...any) datapool.Row {
	f.seen = append(f.seen, sql)
	for frag, v := range f.rows {
		if strings.Contains(sql, frag) {
			return fakeRow{values: v}
		}
	}
	return fakeRow{err: datapool.ErrNoRows}
}

func (f *fakeSQL) Query(context.Context, string, ...any) (datapool.Rows, error) {
	return nil, errors.New("not scripted")
}

type fakeConn struct{ sql *fakeSQL }

func (c fakeConn) SQL() datapool.SQL { return c.sql }
func (c fakeConn) InTx(_ context.Context, fn func(datapool.SQL) error) error {
	return fn(c.sql)
}
func (c fakeConn) Release() {}

type fakeConns struct{ sql *fakeSQL }

func (f fakeConns) For(context.Context, string) (conn, error) { return fakeConn{sql: f.sql}, nil }

func newTestStore(sql *fakeSQL) *postgresStore { return &postgresStore{conns: fakeConns{sql: sql}} }

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestReadFile_RefusesAContentThatDoesNotMatchItsSha256(t *testing.T) {
	entry := []any{"web-recon", "sha256:aa", "r/x@sha256:aa", "d", "", "", "{}", []string{}, time.Now(), true}
	good := newTestStore(&fakeSQL{rows: map[string][]any{
		"FROM agent_skills":      entry,
		"FROM agent_skill_files": {[]byte("guide"), sum([]byte("guide"))},
	}})
	got, err := good.ReadFile(context.Background(), "acme", "web-recon", "sha256:aa", "references/g.md")
	if err != nil || string(got) != "guide" {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}

	// The fixture that fails: the stored content changed after the sha256.
	bad := newTestStore(&fakeSQL{rows: map[string][]any{
		"FROM agent_skills":      entry,
		"FROM agent_skill_files": {[]byte("tampered"), sum([]byte("guide"))},
	}})
	_, err = bad.ReadFile(context.Background(), "acme", "web-recon", "sha256:aa", "references/g.md")
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("ReadFile of a changed content: error = %v, want ErrCorrupt", err)
	}
}

func TestReadFile_NeedsAVersionOfThatName(t *testing.T) {
	s := newTestStore(&fakeSQL{rows: map[string][]any{
		"FROM agent_skill_files": {[]byte("x"), sum([]byte("x"))},
	}})
	// No agent_skills row for the name and digest: the file is not readable.
	if _, err := s.ReadFile(context.Background(), "acme", "other", "sha256:aa", "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestPublish_RefusesAnIncompleteInput(t *testing.T) {
	s := newTestStore(&fakeSQL{})
	if _, err := s.Publish(context.Background(), "acme", "", nil); err == nil {
		t.Error("Publish with no Agent Skill must fail")
	}
	m := &agentskill.Manifest{Name: "web-recon", Description: "d"}
	pulled := &agentskill.Pulled{Manifest: m, Digest: "sha256:aa"}
	if _, err := s.Publish(context.Background(), "acme", "", pulled); err == nil {
		t.Error("Publish with no reference must fail")
	}
}

func TestPublish_MovesTheCurrentFlagInOneTransaction(t *testing.T) {
	sql := &fakeSQL{rows: map[string][]any{
		"FROM agent_skills": {"web-recon", "sha256:aa", "r@sha256:aa", "d", "", "", "{}", []string{}, time.Now(), true},
	}}
	s := newTestStore(sql)
	p := &agentskill.Pulled{
		Manifest: &agentskill.Manifest{Name: "web-recon", Description: "d"},
		Digest:   "sha256:aa",
		Files:    []agentskill.File{{Path: "SKILL.md", Content: []byte("x")}},
	}
	e, err := s.Publish(context.Background(), "acme", "r@sha256:aa", p)
	if err != nil || !e.Current || e.Digest != "sha256:aa" {
		t.Fatalf("Publish = %+v, %v", e, err)
	}
	var clears, sets int
	for _, q := range sql.seen {
		if strings.Contains(q, "SET is_current = false") {
			clears++
		}
		if strings.Contains(q, "SET is_current = true") {
			sets++
		}
	}
	if clears != 1 || sets != 1 {
		t.Errorf("current flag statements: clear %d, set %d, want 1 and 1", clears, sets)
	}
}

func TestLoadAndResolve_NeedTheirKeys(t *testing.T) {
	s := newTestStore(&fakeSQL{})
	if _, err := s.Load(context.Background(), "acme", "web-recon", ""); err == nil {
		t.Error("Load with no digest must fail")
	}
	if _, err := s.Resolve(context.Background(), "acme", "", "web-recon"); err == nil {
		t.Error("Resolve with no mission id must fail")
	}
	if _, err := s.Resolve(context.Background(), "acme", "m1", "web-recon"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Resolve of an unknown name: error = %v, want ErrNotFound", err)
	}
}

type listStore struct {
	Store
	entries []Entry
	err     error
}

func (l listStore) List(context.Context, string, string, bool) ([]Entry, error) {
	return l.entries, l.err
}

func TestToolLister_ListsTheCurrentAgentSkillsAsCatalogEntries(t *testing.T) {
	got, err := ToolLister{Store: listStore{entries: []Entry{{Name: "web-recon", Description: "d"}}}}.
		ListTools(context.Background(), "acme")
	if err != nil || len(got) != 1 {
		t.Fatalf("ListTools = %+v, %v", got, err)
	}
	if got[0].Source != "skill" || got[0].Tool != "web-recon" || got[0].Description != "d" {
		t.Errorf("entry = %+v", got[0])
	}
	boom := errors.New("db down")
	if _, err := (ToolLister{Store: listStore{err: boom}}).ListTools(context.Background(), "acme"); !errors.Is(err, boom) {
		t.Errorf("error = %v, want the store error", err)
	}
}
