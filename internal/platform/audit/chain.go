// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audit — chain.go
//
// Per-tenant hash chain over the Postgres audit_log table.
//
// Every row carries chain_seq (1-based, gapless within a tenant), prev_hash
// (the preceding row's entry_hash) and entry_hash (SHA-256 over prev_hash
// plus the row's own fields). Two kinds of tampering become detectable:
//
//   - editing a stored field changes that row's canonical encoding, so its
//     recomputed entry_hash no longer matches the stored one;
//   - deleting a row leaves a gap in the chain_seq run AND leaves the next
//     row's prev_hash pointing at a hash no surviving row produces.
//
// # What this does not defend against
//
// The chain is unkeyed. It detects an actor who edits or deletes rows but
// cannot rewrite everything after them — which is the realistic case for an
// application-level bug, a stray UPDATE, or a partially-compromised service
// account. It does NOT detect an actor with unrestricted write access to the
// table, who can recompute every subsequent entry_hash. Nor does it detect
// truncation of the newest rows, because nothing outside the table commits
// to where the chain currently ends. Closing either gap requires anchoring
// the chain head somewhere the actor cannot reach — external notarisation,
// or an HMAC key held off-box. Neither is implemented here; do not describe
// this table as tamper-proof.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// chainHashLen is the width of prev_hash / entry_hash in bytes.
const chainHashLen = sha256.Size

// chainGenesis is the prev_hash of the first row in a tenant's chain: 32
// zero bytes. Returned fresh each call so a caller cannot mutate the shared
// value out from under a later hash computation.
func chainGenesis() []byte { return make([]byte, chainHashLen) }

// chainRow is one fully-determined audit_log row — every field that the
// chain commits to, with nothing left to a database default. Writer builds
// these on the way in; VerifyChain reconstructs them on the way out. The two
// must agree field-for-field, which is why both go through canonical().
type chainRow struct {
	Seq        int64
	TenantID   string
	ActorID    string
	ActorType  string
	Action     string
	TargetType string
	TargetID   string
	Decision   string
	Metadata   []byte
	CreatedAt  time.Time
	PrevHash   []byte
	EntryHash  []byte
}

// canonical returns the byte string that entry_hash is taken over.
//
// Every field is length-prefixed rather than separator-joined. With a
// separator, an actor who controls one attacker-supplied field (action and
// target_id both are) could embed the separator and shift field boundaries,
// making two different rows encode identically — the hash would then bless a
// forgery. A 4-byte big-endian length in front of each field makes the
// encoding injective, so distinct rows always produce distinct bytes.
func (r chainRow) canonical() []byte {
	var buf bytes.Buffer

	writeField := func(b []byte) {
		var l [4]byte
		// len(b) is a single audit_log column (tenant/actor/action/target
		// identifiers or the metadata JSON blob) — never remotely close to
		// the 4-byte prefix's ~4GiB ceiling. Clamping rather than gosec's
		// preferred error return keeps canonical() infallible, which every
		// caller (including the hot Writer flush path) depends on.
		l32 := uint32(min(len(b), math.MaxUint32)) //nolint:gosec // clamped, see above
		binary.BigEndian.PutUint32(l[:], l32)
		buf.Write(l[:])
		buf.Write(b)
	}
	writeUint64 := func(v uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		writeField(b[:])
	}

	// r.Seq is the chain_seq bigserial position (1-based, always positive)
	// and CreatedAt.UnixMicro() is a post-epoch audit-log timestamp — both
	// int64 values that are never negative in practice, so the uint64
	// reinterpretation below cannot wrap.
	writeUint64(uint64(r.Seq)) //nolint:gosec // always non-negative, see above
	writeField(r.PrevHash)
	writeField([]byte(r.TenantID))
	writeField([]byte(r.ActorID))
	writeField([]byte(r.ActorType))
	writeField([]byte(r.Action))
	writeField([]byte(r.TargetType))
	writeField([]byte(r.TargetID))
	writeField([]byte(r.Decision))
	writeField(r.Metadata)
	// Microseconds, because that is Postgres' TIMESTAMPTZ resolution: a
	// nanosecond-precision Go timestamp would not survive the round trip and
	// the hash would stop reproducing on read-back.
	writeUint64(uint64(r.CreatedAt.UTC().UnixMicro())) //nolint:gosec // always non-negative, see above

	return buf.Bytes()
}

// computeEntryHash returns the chain hash for r. r.EntryHash is ignored.
func computeEntryHash(r chainRow) []byte {
	sum := sha256.Sum256(r.canonical())
	return sum[:]
}

// tenantAdvisoryKey maps a tenant ID onto the int64 key space of
// pg_advisory_xact_lock. Writers serialise on this per tenant so two
// concurrent flushes cannot read the same chain head and both extend it.
func tenantAdvisoryKey(tenantID string) int64 {
	sum := sha256.Sum256([]byte("gibson.audit_log.chain:" + tenantID))
	// pg_advisory_xact_lock takes a signed bigint key space; the reinterpreted
	// sign bit is irrelevant here — this is a hash-derived lock key, not a
	// count or an offset, so "overflow" has no meaning to guard against.
	return int64(binary.BigEndian.Uint64(sum[:8])) //nolint:gosec // deliberate full-range reinterpretation, see above
}

// chainQuerier is the subset of *sql.DB / *sql.Tx that chainHead needs.
type chainQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// chainHead returns the tenant's current chain position and the entry_hash
// the next row must point at. For a tenant with no chained rows it returns
// (0, genesis) so the first row lands at chain_seq 1.
//
// Callers must already hold the tenant's advisory lock — otherwise the value
// is stale the moment it is read.
func chainHead(ctx context.Context, q chainQuerier, tenantID string) (seq int64, entryHash []byte, err error) {
	const query = `
SELECT chain_seq, entry_hash
FROM   audit_log
WHERE  tenant_id = $1 AND chain_seq IS NOT NULL
ORDER  BY chain_seq DESC
LIMIT  1`

	var (
		gotSeq  int64
		gotHash []byte
	)
	switch scanErr := q.QueryRowContext(ctx, query, tenantID).Scan(&gotSeq, &gotHash); {
	case scanErr == sql.ErrNoRows:
		return 0, chainGenesis(), nil
	case scanErr != nil:
		return 0, nil, fmt.Errorf("audit: read chain head for tenant %q: %w", tenantID, scanErr)
	}

	if len(gotHash) != chainHashLen {
		return 0, nil, fmt.Errorf(
			"audit: chain head for tenant %q has a %d-byte entry_hash, want %d — refusing to extend a corrupt chain",
			tenantID, len(gotHash), chainHashLen)
	}
	return gotSeq, gotHash, nil
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// ChainBreak names the way a tenant's chain failed to verify.
type ChainBreak string

const (
	// ChainIntact means every chained row reproduced its stored hash and
	// the chain_seq run had no gaps.
	ChainIntact ChainBreak = ""

	// ChainBreakAltered means a row's stored fields no longer reproduce its
	// stored entry_hash: the row was edited after it was written.
	ChainBreakAltered ChainBreak = "altered"

	// ChainBreakMissing means the chain_seq run has a gap: a row was
	// deleted.
	ChainBreakMissing ChainBreak = "missing"

	// ChainBreakUnlinked means a row's prev_hash does not match its
	// predecessor's entry_hash: rows were deleted, reordered, or spliced in.
	ChainBreakUnlinked ChainBreak = "unlinked"
)

// ChainReport is the outcome of verifying one tenant's chain.
type ChainReport struct {
	// TenantID is the chain that was verified.
	TenantID string

	// Chained is the number of rows carrying a chain position that were
	// examined — verification stops at the first break, so this counts rows
	// checked, not rows present.
	Chained int

	// Unchained is the number of rows with a NULL chain_seq: written before
	// the chain migration, and therefore outside it. These are NOT verified;
	// a non-zero count is a statement about coverage, not about integrity.
	Unchained int

	// Break is the failure kind, or ChainIntact.
	Break ChainBreak

	// BreakSeq is the chain position at which verification failed. Zero when
	// the chain is intact.
	BreakSeq int64

	// Detail is a human-readable description of the break. Empty when the
	// chain is intact.
	Detail string
}

// Intact reports whether the chain verified end to end.
func (r ChainReport) Intact() bool { return r.Break == ChainIntact }

// VerifyChain recomputes tenantID's hash chain from the stored rows and
// reports the first break, if any.
//
// A nil error means verification ran, not that the chain is intact — check
// ChainReport.Intact. An error means the rows could not be read at all.
func (q *Query) VerifyChain(ctx context.Context, tenantID string) (ChainReport, error) {
	if tenantID == "" {
		return ChainReport{}, errors.New("audit.Query.VerifyChain: tenantID must not be empty")
	}

	report := ChainReport{TenantID: tenantID}

	const unchainedQuery = `SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1 AND chain_seq IS NULL`
	if err := q.db.QueryRowContext(ctx, unchainedQuery, tenantID).Scan(&report.Unchained); err != nil {
		return ChainReport{}, fmt.Errorf("audit.Query.VerifyChain: count unchained rows: %w", err)
	}

	const rowQuery = `
SELECT chain_seq, prev_hash, entry_hash, actor_id, actor_type, action,
       COALESCE(target_type, ''), COALESCE(target_id, ''), COALESCE(decision, ''),
       metadata, created_at
FROM   audit_log
WHERE  tenant_id = $1 AND chain_seq IS NOT NULL
ORDER  BY chain_seq ASC`

	rows, err := q.db.QueryContext(ctx, rowQuery, tenantID)
	if err != nil {
		return ChainReport{}, fmt.Errorf("audit.Query.VerifyChain: read chain: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var (
		expectedSeq int64 = 1
		prevHash          = chainGenesis()
	)
	for rows.Next() {
		r := chainRow{TenantID: tenantID}
		if err := rows.Scan(
			&r.Seq, &r.PrevHash, &r.EntryHash, &r.ActorID, &r.ActorType, &r.Action,
			&r.TargetType, &r.TargetID, &r.Decision, &r.Metadata, &r.CreatedAt,
		); err != nil {
			return ChainReport{}, fmt.Errorf("audit.Query.VerifyChain: scan row: %w", err)
		}
		report.Chained++

		// A gap in the run means rows between expectedSeq and r.Seq are gone.
		if r.Seq != expectedSeq {
			report.Break = ChainBreakMissing
			report.BreakSeq = expectedSeq
			report.Detail = fmt.Sprintf(
				"chain positions %d..%d are absent (next stored position is %d)",
				expectedSeq, r.Seq-1, r.Seq)
			return report, nil
		}

		// A row deleted at the tail of a run, or a spliced-in row, breaks the
		// backward link even when the positions still look contiguous.
		if !bytes.Equal(r.PrevHash, prevHash) {
			report.Break = ChainBreakUnlinked
			report.BreakSeq = r.Seq
			report.Detail = fmt.Sprintf(
				"prev_hash at position %d does not match the preceding entry_hash", r.Seq)
			return report, nil
		}

		if !bytes.Equal(computeEntryHash(r), r.EntryHash) {
			report.Break = ChainBreakAltered
			report.BreakSeq = r.Seq
			report.Detail = fmt.Sprintf(
				"row at position %d does not reproduce its stored entry_hash", r.Seq)
			return report, nil
		}

		prevHash = r.EntryHash
		expectedSeq = r.Seq + 1
	}
	if err := rows.Err(); err != nil {
		return ChainReport{}, fmt.Errorf("audit.Query.VerifyChain: rows iteration: %w", err)
	}

	return report, nil
}
