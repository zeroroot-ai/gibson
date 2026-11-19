// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package agentskillstore keeps the validated content of each published Agent
// Skill in the per-tenant Postgres database (migration 019, epic gibson#1364).
//
// A publish writes one row for each version, keyed by the digest of its OCI
// image, and moves the current flag. A load reads these rows and never the
// registry, so a running mission keeps its digest even when the registry loses
// the image. An old digest stays readable until the tenant deletes the name.
package agentskillstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

var (
	// ErrNotFound marks a name, a digest or a file that the tenant does not have.
	ErrNotFound = errors.New("agentskillstore: not found")
	// ErrCorrupt marks a stored file whose content does not match its sha256.
	ErrCorrupt = errors.New("agentskillstore: the stored content does not match its sha256")
)

// The sources of a version.
const (
	// SourceTenant is a version that the tenant published.
	SourceTenant = "tenant"
	// SourceShared is a copy of a Shared Agent Skill of the operator.
	SourceShared = "shared"
)

// Entry is one published version of an Agent Skill.
type Entry struct {
	Name          string
	Digest        string
	Reference     string
	Description   string
	License       string
	Compatibility string
	Metadata      map[string]string
	AllowedTools  []string
	PublishedAt   time.Time
	// Current is true for the newest publish of the name.
	Current bool
	// Source is SourceTenant or SourceShared.
	Source string
}

// FileInfo names one file of a version.
type FileInfo struct {
	Path string
	Size int
}

// Loaded is the body of one version and the list of its other files.
type Loaded struct {
	Entry Entry
	// Body is the text of SKILL.md after the frontmatter.
	Body  string
	Files []FileInfo
}

// Store reads and writes Agent Skills of one tenant.
type Store interface {
	// Publish stores a pulled version and makes it the current version of its
	// name. source is SourceTenant or SourceShared. It is idempotent for a digest
	// that the tenant already has.
	Publish(ctx context.Context, tenant, reference, source string, p *agentskill.Pulled) (*Entry, error)
	// List returns the current version of each name. With allVersions it
	// returns each version. A non-empty name restricts the list to that name.
	List(ctx context.Context, tenant, name string, allVersions bool) ([]Entry, error)
	// ListPage is List for one page. It returns at most limit entries, in the
	// order of List. With after set it returns the entries that follow it.
	ListPage(ctx context.Context, tenant, name string, allVersions bool, after *PageKey, limit int) ([]Entry, error)
	// Get returns one version. An empty digest means the current version.
	Get(ctx context.Context, tenant, name, digest string) (*Entry, error)
	// Resolve returns the digest that a mission uses for a name. The first call
	// of a mission pins the current digest. A later call returns the same
	// digest, even after a new publish.
	Resolve(ctx context.Context, tenant, missionID, name string) (string, error)
	// Load returns the body of one version by its digest.
	Load(ctx context.Context, tenant, name, digest string) (*Loaded, error)
	// ReadFile returns one file of one version by its digest.
	ReadFile(ctx context.Context, tenant, name, digest, path string) ([]byte, error)
	// Delete removes each version of a name. It reports how many it removed.
	Delete(ctx context.Context, tenant, name string) (int64, error)
}

// conn is one tenant database handle for the life of a call.
type conn interface {
	SQL() datapool.SQL
	InTx(ctx context.Context, fn func(datapool.SQL) error) error
	Release()
}

// conns hands out a conn for each tenant.
type conns interface {
	For(ctx context.Context, tenantID string) (conn, error)
}

type poolConns struct{ pool datapool.Pool }

func (p poolConns) For(ctx context.Context, tenantID string) (conn, error) {
	tid, err := auth.NewTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("agentskillstore: invalid tenant %q: %w", tenantID, err)
	}
	c, err := p.pool.For(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("agentskillstore: acquire conn for %s: %w", tenantID, err)
	}
	return c, nil
}

type postgresStore struct{ conns conns }

// NewPostgresStore builds the production Store over the per-tenant data pool.
// A nil pool is a configuration error and panics at start.
func NewPostgresStore(pool datapool.Pool) Store {
	if pool == nil {
		panic("agentskillstore: NewPostgresStore: pool must not be nil")
	}
	return &postgresStore{conns: poolConns{pool: pool}}
}

var _ Store = (*postgresStore)(nil)

const entryColumns = `name, digest, reference, description, license, compatibility,
	metadata_json, allowed_tools, published_at, is_current, source`

type scanner interface {
	Scan(dest ...any) error
}

func scanEntry(row scanner) (*Entry, error) {
	var (
		e        Entry
		metadata string
	)
	if err := row.Scan(&e.Name, &e.Digest, &e.Reference, &e.Description, &e.License,
		&e.Compatibility, &metadata, &e.AllowedTools, &e.PublishedAt, &e.Current, &e.Source); err != nil {
		return nil, fmt.Errorf("scan Agent Skill row: %w", err)
	}
	if metadata != "" && metadata != "{}" {
		if err := json.Unmarshal([]byte(metadata), &e.Metadata); err != nil {
			return nil, fmt.Errorf("decode the metadata of %s: %w", e.Digest, err)
		}
	}
	e.PublishedAt = e.PublishedAt.UTC()
	return &e, nil
}

func (s *postgresStore) Publish(
	ctx context.Context, tenant, reference, source string, p *agentskill.Pulled,
) (*Entry, error) {
	if p == nil || p.Manifest == nil || p.Digest == "" || reference == "" {
		return nil, errors.New("agentskillstore: publish needs a pulled Agent Skill and its reference")
	}
	if source != SourceTenant && source != SourceShared {
		return nil, fmt.Errorf("agentskillstore: publish: unknown source %q", source)
	}
	m := p.Manifest
	metadata, err := json.Marshal(m.Metadata)
	if err != nil {
		return nil, fmt.Errorf("agentskillstore: encode the metadata: %w", err)
	}
	if m.Metadata == nil {
		metadata = []byte("{}")
	}
	tools := m.AllowedTools
	if tools == nil {
		tools = []string{}
	}
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("agent skill store: acquire conn: %w", err)
	}
	defer c.Release()

	err = c.InTx(ctx, func(q datapool.SQL) error {
		// Two publishes of one name run one after the other. Without the lock
		// each transaction clears a flag that it cannot see yet, and the second
		// one fails on the unique index of the current flag. The lock ends with
		// the transaction.
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "agent_skills:"+m.Name); err != nil {
			return fmt.Errorf("lock the name: %w", err)
		}
		if _, err := q.Exec(ctx,
			`INSERT INTO agent_skills
			   (name, digest, reference, description, license, compatibility, metadata_json, allowed_tools, source)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			 ON CONFLICT (digest) DO NOTHING`,
			m.Name, p.Digest, reference, m.Description, m.License, m.Compatibility, string(metadata), tools, source); err != nil {
			return fmt.Errorf("insert version: %w", err)
		}
		for _, f := range p.Files {
			sum := sha256.Sum256(f.Content)
			if _, err := q.Exec(ctx,
				`INSERT INTO agent_skill_files (digest, path, content, sha256)
				 VALUES ($1,$2,$3,$4)
				 ON CONFLICT (digest, path) DO NOTHING`,
				p.Digest, f.Path, f.Content, hex.EncodeToString(sum[:])); err != nil {
				return fmt.Errorf("insert file %q: %w", f.Path, err)
			}
		}
		if _, err := q.Exec(ctx,
			`UPDATE agent_skills SET is_current = false WHERE name = $1 AND is_current AND digest <> $2`,
			m.Name, p.Digest); err != nil {
			return fmt.Errorf("clear the current flag: %w", err)
		}
		if _, err := q.Exec(ctx,
			`UPDATE agent_skills SET is_current = true WHERE digest = $1`, p.Digest); err != nil {
			return fmt.Errorf("set the current flag: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("agentskillstore: publish %s: %w", m.Name, err)
	}
	return s.Get(ctx, tenant, m.Name, p.Digest)
}

func (s *postgresStore) List(ctx context.Context, tenant, name string, allVersions bool) ([]Entry, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("agent skill store: acquire conn: %w", err)
	}
	defer c.Release()

	rows, err := c.SQL().Query(ctx,
		`SELECT `+entryColumns+` FROM agent_skills
		 WHERE ($1 = '' OR name = $1) AND ($2 OR is_current)
		 ORDER BY name ASC, published_at DESC, digest ASC`,
		name, allVersions)
	if err != nil {
		return nil, fmt.Errorf("agentskillstore: list: %w", err)
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		e, scanErr := scanEntry(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("agentskillstore: list: %w", scanErr)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agentskillstore: list rows: %w", err)
	}
	return out, nil
}

// PageKey is the position of one entry in the order of List: the name, then
// the newest publish first, then the digest. Its fields are unique together.
type PageKey struct {
	Name        string
	PublishedAt time.Time
	Digest      string
}

func (s *postgresStore) ListPage(
	ctx context.Context, tenant, name string, allVersions bool, after *PageKey, limit int,
) ([]Entry, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("agent skill store: acquire conn: %w", err)
	}
	defer c.Release()

	var afterName, afterDigest string
	var afterAt time.Time
	if after != nil {
		afterName, afterAt, afterDigest = after.Name, after.PublishedAt, after.Digest
	}
	rows, err := c.SQL().Query(ctx,
		`SELECT `+entryColumns+` FROM agent_skills
		 WHERE ($1 = '' OR name = $1) AND ($2 OR is_current)
		   AND (NOT $3 OR name > $4
		        OR (name = $4 AND published_at < $5)
		        OR (name = $4 AND published_at = $5 AND digest > $6))
		 ORDER BY name ASC, published_at DESC, digest ASC
		 LIMIT $7`,
		name, allVersions, after != nil, afterName, afterAt, afterDigest, limit)
	if err != nil {
		return nil, fmt.Errorf("agentskillstore: list page: %w", err)
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		e, scanErr := scanEntry(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("agentskillstore: list page: %w", scanErr)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agentskillstore: list page rows: %w", err)
	}
	return out, nil
}

func (s *postgresStore) Get(ctx context.Context, tenant, name, digest string) (*Entry, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("agent skill store: acquire conn: %w", err)
	}
	defer c.Release()
	return getEntry(ctx, c.SQL(), name, digest)
}

func getEntry(ctx context.Context, q datapool.SQL, name, digest string) (*Entry, error) {
	row := q.QueryRow(ctx,
		`SELECT `+entryColumns+` FROM agent_skills
		 WHERE name = $1 AND (($2 = '' AND is_current) OR digest = $2)`,
		name, digest)
	e, err := scanEntry(row)
	if errors.Is(err, datapool.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, describe(name, digest))
	}
	if err != nil {
		return nil, fmt.Errorf("agentskillstore: get %s: %w", name, err)
	}
	return e, nil
}

func describe(name, digest string) string {
	if digest == "" {
		return name
	}
	return name + "@" + digest
}

func (s *postgresStore) Resolve(ctx context.Context, tenant, missionID, name string) (string, error) {
	if missionID == "" {
		return "", errors.New("agentskillstore: resolve needs a mission id")
	}
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return "", fmt.Errorf("agent skill store: acquire conn: %w", err)
	}
	defer c.Release()

	var digest string
	err = c.InTx(ctx, func(q datapool.SQL) error {
		// The first load of the mission pins the current digest. A later load
		// reads the pin, so a new publish does not change what the mission sees.
		if _, err := q.Exec(ctx,
			`INSERT INTO agent_skill_mission_pins (mission_id, name, digest)
			 SELECT $1, name, digest FROM agent_skills WHERE name = $2 AND is_current
			 ON CONFLICT (mission_id, name) DO NOTHING`,
			missionID, name); err != nil {
			return fmt.Errorf("pin: %w", err)
		}
		row := q.QueryRow(ctx,
			`SELECT digest FROM agent_skill_mission_pins WHERE mission_id = $1 AND name = $2`,
			missionID, name)
		if err := row.Scan(&digest); err != nil {
			if errors.Is(err, datapool.ErrNoRows) {
				return fmt.Errorf("%w: %s", ErrNotFound, name)
			}
			return fmt.Errorf("read the pin: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("agentskillstore: resolve %s: %w", name, err)
	}
	return digest, nil
}

func (s *postgresStore) Load(ctx context.Context, tenant, name, digest string) (*Loaded, error) {
	if digest == "" {
		return nil, errors.New("agentskillstore: load needs a digest")
	}
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("agent skill store: acquire conn: %w", err)
	}
	defer c.Release()
	q := c.SQL()

	entry, err := getEntry(ctx, q, name, digest)
	if err != nil {
		return nil, err
	}
	skill, err := readFile(ctx, q, digest, agentskill.SkillFile)
	if err != nil {
		return nil, err
	}
	m, err := agentskill.ParseSkillFile(skill)
	if err != nil {
		return nil, fmt.Errorf("agentskillstore: the stored %s of %s is not valid: %w", agentskill.SkillFile, digest, err)
	}
	rows, err := q.Query(ctx,
		`SELECT path, octet_length(content) FROM agent_skill_files WHERE digest = $1 ORDER BY path`, digest)
	if err != nil {
		return nil, fmt.Errorf("agentskillstore: list the files of %s: %w", digest, err)
	}
	defer rows.Close()
	var files []FileInfo
	for rows.Next() {
		var f FileInfo
		if err := rows.Scan(&f.Path, &f.Size); err != nil {
			return nil, fmt.Errorf("agentskillstore: scan a file row: %w", err)
		}
		if f.Path != agentskill.SkillFile {
			files = append(files, f)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agentskillstore: file rows: %w", err)
	}
	return &Loaded{Entry: *entry, Body: m.Body, Files: files}, nil
}

func (s *postgresStore) ReadFile(ctx context.Context, tenant, name, digest, path string) ([]byte, error) {
	if digest == "" {
		return nil, errors.New("agentskillstore: read a file needs a digest")
	}
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("agent skill store: acquire conn: %w", err)
	}
	defer c.Release()
	q := c.SQL()
	// The file is read only through a version that the tenant has under this name.
	if _, err := getEntry(ctx, q, name, digest); err != nil {
		return nil, err
	}
	return readFile(ctx, q, digest, path)
}

// readFile reads one file and checks its content against the stored sha256.
func readFile(ctx context.Context, q datapool.SQL, digest, path string) ([]byte, error) {
	var (
		content []byte
		want    string
	)
	row := q.QueryRow(ctx, `SELECT content, sha256 FROM agent_skill_files WHERE digest = $1 AND path = $2`, digest, path)
	if err := row.Scan(&content, &want); err != nil {
		if errors.Is(err, datapool.ErrNoRows) {
			return nil, fmt.Errorf("%w: file %q of %s", ErrNotFound, path, digest)
		}
		return nil, fmt.Errorf("agentskillstore: read %q of %s: %w", path, digest, err)
	}
	sum := sha256.Sum256(content)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return nil, fmt.Errorf("%w: file %q of %s", ErrCorrupt, path, digest)
	}
	return content, nil
}

func (s *postgresStore) Delete(ctx context.Context, tenant, name string) (int64, error) {
	c, err := s.conns.For(ctx, tenant)
	if err != nil {
		return 0, fmt.Errorf("agent skill store: acquire conn: %w", err)
	}
	defer c.Release()
	// The files and the pins cascade on the foreign key.
	n, err := c.SQL().Exec(ctx, `DELETE FROM agent_skills WHERE name = $1`, name)
	if err != nil {
		return 0, fmt.Errorf("agentskillstore: delete %s: %w", name, err)
	}
	if n == 0 {
		return 0, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return n, nil
}
