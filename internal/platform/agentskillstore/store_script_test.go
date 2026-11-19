// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentskillstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// scrDB answers each statement from a function that the test sets. The SQL
// itself needs a real Postgres, and the integration test covers it.

var errScr = errors.New("scripted failure")

type scrRow struct {
	values []any
	err    error
}

func (r scrRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, v := range r.values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(v))
	}
	return nil
}

type scrRows struct {
	rows    [][]any
	scanErr error
	err     error
	pos     int
}

func (r *scrRows) Next() bool { r.pos++; return r.pos <= len(r.rows) }
func (r *scrRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	return scrRow{values: r.rows[r.pos-1]}.Scan(dest...)
}
func (r *scrRows) Err() error { return r.err }
func (r *scrRows) Close()     {}

type scrDB struct {
	forErr   error
	exec     func(sql string) (int64, error)
	queryRow func(sql string) datapool.Row
	query    func(sql string) (datapool.Rows, error)
	released int
	seen     []string
}

func (d *scrDB) For(context.Context, string) (conn, error) {
	if d.forErr != nil {
		return nil, d.forErr
	}
	return d, nil
}
func (d *scrDB) SQL() datapool.SQL { return d }
func (d *scrDB) Release()          { d.released++ }
func (d *scrDB) InTx(_ context.Context, fn func(datapool.SQL) error) error {
	return fn(d)
}
func (d *scrDB) Exec(_ context.Context, sql string, _ ...any) (int64, error) {
	d.seen = append(d.seen, sql)
	return d.exec(sql)
}
func (d *scrDB) QueryRow(_ context.Context, sql string, _ ...any) datapool.Row {
	d.seen = append(d.seen, sql)
	return d.queryRow(sql)
}
func (d *scrDB) Query(_ context.Context, sql string, _ ...any) (datapool.Rows, error) {
	d.seen = append(d.seen, sql)
	return d.query(sql)
}

func scrStore(db *scrDB) *postgresStore { return &postgresStore{conns: db} }

var scrTime = time.Date(2026, 11, 1, 10, 0, 0, 0, time.FixedZone("x", 3600))

func scrEntryRow(name, digest, metadata string, current bool) []any {
	return []any{name, digest, "r/" + name + "@" + digest, "d", "MIT", "any", metadata,
		[]string{"Read"}, scrTime, current, SourceTenant}
}

func scrOK(string) (int64, error) { return 1, nil }

func scrRowFn(values ...any) func(string) datapool.Row {
	return func(string) datapool.Row { return scrRow{values: values} }
}

func scrErrRow(err error) func(string) datapool.Row {
	return func(string) datapool.Row { return scrRow{err: err} }
}

func TestScanEntry(t *testing.T) {
	e, err := scanEntry(scrRow{values: scrEntryRow("web-recon", "sha256:aa", `{"team":"red"}`, true)})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"team": "red"}, e.Metadata)
	assert.Equal(t, []string{"Read"}, e.AllowedTools)
	assert.Equal(t, time.UTC, e.PublishedAt.Location())
	assert.True(t, e.PublishedAt.Equal(scrTime))
	assert.True(t, e.Current)

	for _, empty := range []string{"", "{}"} {
		e, err = scanEntry(scrRow{values: scrEntryRow("n", "d", empty, false)})
		require.NoError(t, err)
		assert.Nil(t, e.Metadata, "metadata %q is no map", empty)
	}

	_, err = scanEntry(scrRow{values: scrEntryRow("n", "sha256:bb", `{`, false)})
	require.ErrorContains(t, err, "decode the metadata of sha256:bb")

	_, err = scanEntry(scrRow{err: errScr})
	require.ErrorIs(t, err, errScr)
}

func scrPulled() *agentskill.Pulled {
	return &agentskill.Pulled{
		Manifest: &agentskill.Manifest{
			Name: "web-recon", Description: "d", License: "MIT", Metadata: map[string]string{"k": "v"},
			AllowedTools: []string{"Read"},
		},
		Digest: "sha256:aa",
		Files: []agentskill.File{
			{Path: "SKILL.md", Content: []byte("x")},
			{Path: "references/g.md", Content: []byte("y")},
		},
	}
}

func TestPublish_RunsEachStatementInOrder(t *testing.T) {
	db := &scrDB{exec: scrOK, queryRow: scrRowFn(scrEntryRow("web-recon", "sha256:aa", `{"k":"v"}`, true)...)}

	e, err := scrStore(db).Publish(context.Background(), "acme", "r@sha256:aa", SourceShared, scrPulled())

	require.NoError(t, err)
	assert.Equal(t, "sha256:aa", e.Digest)
	require.Len(t, db.seen, 7)
	order := []string{
		"pg_advisory_xact_lock", "INSERT INTO agent_skills", "INSERT INTO agent_skill_files",
		"INSERT INTO agent_skill_files", "SET is_current = false", "SET is_current = true", "FROM agent_skills",
	}
	for i, frag := range order {
		assert.Contains(t, db.seen[i], frag, "statement %d", i)
	}
	assert.Equal(t, 2, db.released, "the publish and the read back each release a conn")
}

func TestPublish_FillsDefaultsForAnEmptyManifest(t *testing.T) {
	p := scrPulled()
	p.Manifest.Metadata, p.Manifest.AllowedTools, p.Files = nil, nil, nil
	db := &scrDB{exec: scrOK, queryRow: scrRowFn(scrEntryRow("web-recon", "sha256:aa", "{}", true)...)}

	_, err := scrStore(db).Publish(context.Background(), "acme", "r@sha256:aa", SourceTenant, p)

	require.NoError(t, err)
	assert.Len(t, db.seen, 5, "no file statement for a version with no file")
}

func TestPublish_StopsAtTheFirstFailingStatement(t *testing.T) {
	tests := []struct {
		fragment string
		want     string
	}{
		{"pg_advisory_xact_lock", "lock the name"},
		{"INSERT INTO agent_skills", "insert version"},
		{"INSERT INTO agent_skill_files", `insert file "SKILL.md"`},
		{"SET is_current = false", "clear the current flag"},
		{"SET is_current = true", "set the current flag"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			db := &scrDB{exec: func(sql string) (int64, error) {
				if strings.Contains(sql, tt.fragment) {
					return 0, errScr
				}
				return 1, nil
			}}
			e, err := scrStore(db).Publish(context.Background(), "acme", "r@sha256:aa", SourceTenant, scrPulled())
			require.ErrorIs(t, err, errScr)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, e)
		})
	}

	e, err := scrStore(&scrDB{forErr: errScr}).Publish(context.Background(), "acme", "r", SourceTenant, scrPulled())
	require.ErrorIs(t, err, errScr)
	assert.Nil(t, e)
}

func TestList(t *testing.T) {
	db := &scrDB{query: func(string) (datapool.Rows, error) {
		return &scrRows{rows: [][]any{
			scrEntryRow("a", "sha256:1", "{}", true), scrEntryRow("b", "sha256:2", "{}", true),
		}}, nil
	}}

	got, err := scrStore(db).List(context.Background(), "acme", "", true)

	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "a", got[0].Name)
	assert.Equal(t, "b", got[1].Name)
	assert.Contains(t, db.seen[0], "ORDER BY name ASC")
	assert.Equal(t, 1, db.released)
}

func TestList_Failures(t *testing.T) {
	tests := []struct {
		name string
		db   *scrDB
		want string
	}{
		{"no conn", &scrDB{forErr: errScr}, "scripted failure"},
		{"query fails", &scrDB{query: func(string) (datapool.Rows, error) { return nil, errScr }}, "agentskillstore: list"},
		{"scan fails", &scrDB{query: func(string) (datapool.Rows, error) {
			return &scrRows{rows: [][]any{scrEntryRow("a", "d", "{}", true)}, scanErr: errScr}, nil
		}}, "scan Agent Skill row"},
		{"bad metadata", &scrDB{query: func(string) (datapool.Rows, error) {
			return &scrRows{rows: [][]any{scrEntryRow("a", "d", "{", true)}}, nil
		}}, "decode the metadata"},
		{"rows fail", &scrDB{query: func(string) (datapool.Rows, error) {
			return &scrRows{err: errScr}, nil
		}}, "list rows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scrStore(tt.db).List(context.Background(), "acme", "a", false)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
		})
	}
}

func TestGet(t *testing.T) {
	db := &scrDB{queryRow: scrRowFn(scrEntryRow("a", "sha256:1", "{}", true)...)}
	got, err := scrStore(db).Get(context.Background(), "acme", "a", "")
	require.NoError(t, err)
	assert.Equal(t, "sha256:1", got.Digest)

	tests := []struct {
		name   string
		db     *scrDB
		wantIs error
		want   string
	}{
		{"no conn", &scrDB{forErr: errScr}, errScr, ""},
		{"name only", &scrDB{queryRow: scrErrRow(datapool.ErrNoRows)}, ErrNotFound, ": a"},
		{"read fails", &scrDB{queryRow: scrErrRow(errScr)}, errScr, "get a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scrStore(tt.db).Get(context.Background(), "acme", "a", "")
			require.ErrorIs(t, err, tt.wantIs)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
		})
	}

	_, err = scrStore(&scrDB{queryRow: scrErrRow(datapool.ErrNoRows)}).Get(context.Background(), "acme", "a", "sha256:9")
	require.ErrorIs(t, err, ErrNotFound)
	assert.Contains(t, err.Error(), "a@sha256:9", "the message names the digest")
}

func TestResolve(t *testing.T) {
	db := &scrDB{exec: scrOK, queryRow: scrRowFn("sha256:pin")}
	got, err := scrStore(db).Resolve(context.Background(), "acme", "m1", "web-recon")
	require.NoError(t, err)
	assert.Equal(t, "sha256:pin", got)
	require.Len(t, db.seen, 2)
	assert.Contains(t, db.seen[0], "agent_skill_mission_pins")

	tests := []struct {
		name   string
		db     *scrDB
		wantIs error
		want   string
	}{
		{"no conn", &scrDB{forErr: errScr}, errScr, ""},
		{"pin fails", &scrDB{exec: func(string) (int64, error) { return 0, errScr }}, errScr, "pin"},
		{"no pin row", &scrDB{exec: scrOK, queryRow: scrErrRow(datapool.ErrNoRows)}, ErrNotFound, "web-recon"},
		{"pin read fails", &scrDB{exec: scrOK, queryRow: scrErrRow(errScr)}, errScr, "read the pin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scrStore(tt.db).Resolve(context.Background(), "acme", "m1", "web-recon")
			require.ErrorIs(t, err, tt.wantIs)
			assert.Contains(t, err.Error(), tt.want)
			assert.Empty(t, got)
		})
	}
}

const scrSkillMD = "---\nname: web-recon\ndescription: Find web hosts.\n---\nUse the tool.\n"

// scrLoadDB answers a load: the entry, the SKILL.md file, then the file list.
func scrLoadDB(skill []byte, files *scrRows) *scrDB {
	return &scrDB{
		queryRow: func(sql string) datapool.Row {
			if strings.Contains(sql, "FROM agent_skill_files") {
				return scrRow{values: []any{skill, scrSum(skill)}}
			}
			return scrRow{values: scrEntryRow("web-recon", "sha256:aa", "{}", true)}
		},
		query: func(string) (datapool.Rows, error) { return files, nil },
	}
}

func scrSum(b []byte) string { return sum(b) }

func TestLoad(t *testing.T) {
	files := &scrRows{rows: [][]any{
		{"SKILL.md", 70}, {"references/g.md", 12},
	}}
	db := scrLoadDB([]byte(scrSkillMD), files)

	got, err := scrStore(db).Load(context.Background(), "acme", "web-recon", "sha256:aa")

	require.NoError(t, err)
	assert.Equal(t, "Use the tool.\n", got.Body)
	assert.Equal(t, "web-recon", got.Entry.Name)
	assert.Equal(t, []FileInfo{{Path: "references/g.md", Size: 12}}, got.Files, "SKILL.md is not an extra file")
}

func TestLoad_Failures(t *testing.T) {
	skill := []byte(scrSkillMD)
	tests := []struct {
		name   string
		db     *scrDB
		wantIs error
		want   string
	}{
		{"no conn", &scrDB{forErr: errScr}, errScr, ""},
		{"no entry", &scrDB{queryRow: scrErrRow(datapool.ErrNoRows)}, ErrNotFound, ""},
		{"no SKILL.md", &scrDB{queryRow: func(sql string) datapool.Row {
			if strings.Contains(sql, "FROM agent_skill_files") {
				return scrRow{err: datapool.ErrNoRows}
			}
			return scrRow{values: scrEntryRow("web-recon", "sha256:aa", "{}", true)}
		}}, ErrNotFound, "SKILL.md"},
		{"SKILL.md is not valid", scrLoadDB([]byte("no frontmatter"), &scrRows{}), nil, "is not valid"},
		{"file list fails", func() *scrDB {
			d := scrLoadDB(skill, nil)
			d.query = func(string) (datapool.Rows, error) { return nil, errScr }
			return d
		}(), errScr, "list the files"},
		{"file scan fails", scrLoadDB(skill, &scrRows{rows: [][]any{{"a", 1}}, scanErr: errScr}), errScr,
			"scan a file row"},
		{"file rows fail", scrLoadDB(skill, &scrRows{err: errScr}), errScr, "file rows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scrStore(tt.db).Load(context.Background(), "acme", "web-recon", "sha256:aa")
			require.Error(t, err)
			if tt.wantIs != nil {
				require.ErrorIs(t, err, tt.wantIs)
			}
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
		})
	}
}

func TestReadFile_Failures(t *testing.T) {
	_, err := scrStore(&scrDB{}).ReadFile(context.Background(), "acme", "web-recon", "", "a")
	require.ErrorContains(t, err, "needs a digest")

	_, err = scrStore(&scrDB{forErr: errScr}).ReadFile(context.Background(), "acme", "web-recon", "sha256:aa", "a")
	require.ErrorIs(t, err, errScr)

	entryThen := func(file datapool.Row) *scrDB {
		return &scrDB{queryRow: func(sql string) datapool.Row {
			if strings.Contains(sql, "FROM agent_skill_files") {
				return file
			}
			return scrRow{values: scrEntryRow("web-recon", "sha256:aa", "{}", true)}
		}}
	}
	_, err = scrStore(entryThen(scrRow{err: datapool.ErrNoRows})).
		ReadFile(context.Background(), "acme", "web-recon", "sha256:aa", "gone.md")
	require.ErrorIs(t, err, ErrNotFound)
	assert.Contains(t, err.Error(), `file "gone.md"`)

	_, err = scrStore(entryThen(scrRow{err: errScr})).
		ReadFile(context.Background(), "acme", "web-recon", "sha256:aa", "a.md")
	require.ErrorIs(t, err, errScr)
	assert.Contains(t, err.Error(), `read "a.md"`)

	got, err := scrStore(entryThen(scrRow{values: []any{[]byte("ok"), sum([]byte("ok"))}})).
		ReadFile(context.Background(), "acme", "web-recon", "sha256:aa", "a.md")
	require.NoError(t, err)
	assert.Equal(t, "ok", string(got))
}

func TestDelete(t *testing.T) {
	db := &scrDB{exec: func(string) (int64, error) { return 3, nil }}
	n, err := scrStore(db).Delete(context.Background(), "acme", "web-recon")
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
	assert.Equal(t, 1, db.released)

	tests := []struct {
		name   string
		db     *scrDB
		wantIs error
	}{
		{"no conn", &scrDB{forErr: errScr}, errScr},
		{"exec fails", &scrDB{exec: func(string) (int64, error) { return 0, errScr }}, errScr},
		{"no such name", &scrDB{exec: func(string) (int64, error) { return 0, nil }}, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := scrStore(tt.db).Delete(context.Background(), "acme", "web-recon")
			require.ErrorIs(t, err, tt.wantIs)
			assert.Zero(t, n)
		})
	}
}

// scrPool answers only For.
type scrPool struct {
	datapool.Pool
	err error
}

func (p scrPool) For(context.Context, auth.TenantID) (*datapool.Conn, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &datapool.Conn{}, nil
}

func TestPoolConns_For(t *testing.T) {
	_, err := poolConns{pool: scrPool{}}.For(context.Background(), "Not A Tenant!")
	require.ErrorContains(t, err, "invalid tenant")

	_, err = poolConns{pool: scrPool{err: errScr}}.For(context.Background(), "acme")
	require.ErrorIs(t, err, errScr)
	assert.Contains(t, err.Error(), "acquire conn for acme")

	c, err := poolConns{pool: scrPool{}}.For(context.Background(), "acme")
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestNewPostgresStore(t *testing.T) {
	assert.Panics(t, func() { NewPostgresStore(nil) }, "a nil pool is a configuration error")
	assert.IsType(t, &postgresStore{}, NewPostgresStore(scrPool{}))
}

func TestListPage(t *testing.T) {
	db := &scrDB{query: func(string) (datapool.Rows, error) {
		return &scrRows{rows: [][]any{
			scrEntryRow("a", "sha256:1", "{}", true), scrEntryRow("b", "sha256:2", "{}", true),
		}}, nil
	}}
	after := KeyOf(Entry{Name: "a", Digest: "sha256:0", PublishedAt: time.Unix(10, 0)})

	got, err := scrStore(db).ListPage(context.Background(), "acme", "", true, &after, 2)

	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "b", got[1].Name)
	assert.Contains(t, db.seen[0], "ORDER BY name ASC, published_at DESC, digest ASC")
	assert.Equal(t, 1, db.released)

	first, err := scrStore(db).ListPage(context.Background(), "acme", "", false, nil, 2)
	require.NoError(t, err)
	assert.Len(t, first, 2)
}

func TestListPage_Failures(t *testing.T) {
	tests := []struct {
		name string
		db   *scrDB
		want string
	}{
		{"no conn", &scrDB{forErr: errScr}, "scripted failure"},
		{"query fails", &scrDB{query: func(string) (datapool.Rows, error) { return nil, errScr }}, "list page"},
		{"scan fails", &scrDB{query: func(string) (datapool.Rows, error) {
			return &scrRows{rows: [][]any{scrEntryRow("a", "d", "{}", true)}, scanErr: errScr}, nil
		}}, "scan Agent Skill row"},
		{"rows fail", &scrDB{query: func(string) (datapool.Rows, error) {
			return &scrRows{err: errScr}, nil
		}}, "list page rows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scrStore(tt.db).ListPage(context.Background(), "acme", "a", false, nil, 5)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
		})
	}
}
