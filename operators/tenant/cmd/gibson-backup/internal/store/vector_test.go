// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup/internal/store"
)

// vectorPoint mirrors the NDJSON record format for assertion helpers.
type vectorPoint struct {
	ID        string            `json:"id"`
	Embedding string            `json:"embedding"`
	Payload   map[string]string `json:"payload,omitempty"`
}

// newMiniredis starts an in-process Redis stub and returns it plus a go-redis
// client connected to it.
func newMiniredis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

// vectorDSN returns a redis:// DSN pointing at mr with the given index name.
func vectorDSN(mr *miniredis.Miniredis, indexName string) string {
	return fmt.Sprintf("redis://%s/0?index=%s", mr.Addr(), indexName)
}

// seedHash inserts a single vector hash into the miniredis instance at the
// canonical key vec:<tenant>:<id>.
func seedHash(t *testing.T, client *redis.Client, keyPrefix, id, embedding string, payload map[string]string) {
	t.Helper()
	ctx := context.Background()
	key := keyPrefix + id
	fields := make([]any, 0, 2+len(payload)*2)
	fields = append(fields, "embedding", embedding)
	for k, v := range payload {
		fields = append(fields, k, v)
	}
	if err := client.HSet(ctx, key, fields...).Err(); err != nil {
		t.Fatalf("seed hash %s: %v", key, err)
	}
}

// parseNDJSON decodes all NDJSON lines from buf into a slice of vectorPoints
// sorted by ID for deterministic comparison.
func parseNDJSON(t *testing.T, buf *bytes.Buffer) []vectorPoint {
	t.Helper()
	var pts []vectorPoint
	dec := json.NewDecoder(buf)
	for dec.More() {
		var p vectorPoint
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode NDJSON: %v", err)
		}
		pts = append(pts, p)
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i].ID < pts[j].ID })
	return pts
}

// TestVectorBackupRoundTrip inserts 3 hashes, backs them up, restores into a
// fresh miniredis, and verifies the hashes match the originals.
func TestVectorBackupRoundTrip(t *testing.T) {
	const indexName = "vector_idx:tenant_acme"
	const keyPrefix = "vec:tenant_acme:"

	srcMR, srcClient := newMiniredis(t)

	seeds := []struct {
		id        string
		embedding string
		payload   map[string]string
	}{
		{"uuid-001", "emb\x00\x01\x02", map[string]string{"text": "hello world", "source": "doc1"}},
		{"uuid-002", "emb\xFF\xFE\xFD", map[string]string{"text": "foo bar"}},
		{"uuid-003", "\x00\x01\x02\x03\x04", nil},
	}

	for _, s := range seeds {
		seedHash(t, srcClient, keyPrefix, s.id, s.embedding, s.payload)
	}

	ctx := context.Background()
	dsn := vectorDSN(srcMR, indexName)

	// Backup.
	var buf bytes.Buffer
	n, digest, err := store.VectorBackup(ctx, dsn, &buf)
	if err != nil {
		t.Fatalf("VectorBackup: %v", err)
	}
	if n == 0 {
		t.Error("VectorBackup: wrote 0 bytes")
	}
	if digest == "" {
		t.Error("VectorBackup: empty digest")
	}
	if int64(buf.Len()) != n {
		t.Errorf("VectorBackup: reported n=%d but buf.Len()=%d", n, buf.Len())
	}

	// Restore into a fresh miniredis.
	dstMR, dstClient := newMiniredis(t)
	dstDSN := vectorDSN(dstMR, indexName)

	if err := store.VectorRestore(ctx, dstDSN, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("VectorRestore: %v", err)
	}

	// Verify all hashes match the originals.
	for _, s := range seeds {
		key := keyPrefix + s.id
		got, err := dstClient.HGetAll(ctx, key).Result()
		if err != nil {
			t.Errorf("HGetAll %s: %v", key, err)
			continue
		}
		if got["embedding"] != s.embedding {
			t.Errorf("key %s: embedding mismatch: got %q want %q", key, got["embedding"], s.embedding)
		}
		for k, wantV := range s.payload {
			if got[k] != wantV {
				t.Errorf("key %s: payload[%s] = %q, want %q", key, k, got[k], wantV)
			}
		}
	}
}

// TestVectorBackupEmpty verifies that backing up an empty DB produces 0 bytes
// and no error.
func TestVectorBackupEmpty(t *testing.T) {
	mr, _ := newMiniredis(t)
	dsn := vectorDSN(mr, "vector_idx:tenant_empty")

	ctx := context.Background()
	var buf bytes.Buffer
	n, digest, err := store.VectorBackup(ctx, dsn, &buf)
	if err != nil {
		t.Fatalf("VectorBackup on empty DB: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes for empty DB, got %d", n)
	}
	// Digest of empty input is the SHA-256 of zero bytes.
	wantDigest := hex.EncodeToString(sha256.New().Sum(nil))
	if digest != wantDigest {
		t.Errorf("empty digest: got %s want %s", digest, wantDigest)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty buffer, got %d bytes", buf.Len())
	}
}

// TestVectorBackupDigestCorrect verifies the returned digest equals sha256 of
// the written bytes.
func TestVectorBackupDigestCorrect(t *testing.T) {
	mr, client := newMiniredis(t)
	const keyPrefix = "vec:tenant_foo:"
	seedHash(t, client, keyPrefix, "id-1", "some embedding bytes", map[string]string{"k": "v"})

	ctx := context.Background()
	dsn := vectorDSN(mr, "vector_idx:tenant_foo")

	var buf bytes.Buffer
	_, digest, err := store.VectorBackup(ctx, dsn, &buf)
	if err != nil {
		t.Fatalf("VectorBackup: %v", err)
	}

	h := sha256.New()
	h.Write(buf.Bytes())
	wantDigest := hex.EncodeToString(h.Sum(nil))

	if digest != wantDigest {
		t.Errorf("digest mismatch: got %s want %s", digest, wantDigest)
	}
}

// TestVectorBackupMissingIndexParam verifies that a DSN without ?index= returns
// an error.
func TestVectorBackupMissingIndexParam(t *testing.T) {
	mr, _ := newMiniredis(t)
	// No ?index= param.
	dsn := fmt.Sprintf("redis://%s/0", mr.Addr())

	ctx := context.Background()
	_, _, err := store.VectorBackup(ctx, dsn, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for DSN missing ?index=, got nil")
	}
}

// TestVectorRestoreMissingIndexParam verifies that VectorRestore also rejects a
// DSN without ?index=.
func TestVectorRestoreMissingIndexParam(t *testing.T) {
	mr, _ := newMiniredis(t)
	dsn := fmt.Sprintf("redis://%s/0", mr.Addr())

	ctx := context.Background()
	err := store.VectorRestore(ctx, dsn, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for DSN missing ?index=, got nil")
	}
}

// TestVectorParseDSN validates that a well-formed DSN is parsed without error
// by round-tripping a minimal backup (empty DB, valid index param).
func TestVectorParseDSN(t *testing.T) {
	mr, _ := newMiniredis(t)
	// Construct a DSN with password, host, db, and index — even though miniredis
	// ignores auth, go-redis must not reject the URL.
	dsn := fmt.Sprintf("redis://:secretpass@%s/0?index=vector_idx:tenant_bar", mr.Addr())

	ctx := context.Background()
	var buf bytes.Buffer
	n, _, err := store.VectorBackup(ctx, dsn, &buf)
	if err != nil {
		t.Fatalf("VectorBackup with full DSN: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes for empty DB, got %d", n)
	}
}

// TestVectorNDJSONFormat verifies that the backup output is valid NDJSON and
// that the embedding field is base64-encoded.
func TestVectorNDJSONFormat(t *testing.T) {
	mr, client := newMiniredis(t)
	const keyPrefix = "vec:tenant_ndjson:"
	rawEmb := "\x00\x01\x02\x03"
	seedHash(t, client, keyPrefix, "pt-1", rawEmb, map[string]string{"meta": "data"})

	ctx := context.Background()
	dsn := vectorDSN(mr, "vector_idx:tenant_ndjson")

	var buf bytes.Buffer
	if _, _, err := store.VectorBackup(ctx, dsn, &buf); err != nil {
		t.Fatalf("VectorBackup: %v", err)
	}

	pts := parseNDJSON(t, &buf)
	if len(pts) != 1 {
		t.Fatalf("expected 1 NDJSON record, got %d", len(pts))
	}

	pt := pts[0]
	if pt.ID != "pt-1" {
		t.Errorf("ID: got %q want %q", pt.ID, "pt-1")
	}
	wantEmb := base64.StdEncoding.EncodeToString([]byte(rawEmb))
	if pt.Embedding != wantEmb {
		t.Errorf("Embedding: got %q want %q", pt.Embedding, wantEmb)
	}
	if pt.Payload["meta"] != "data" {
		t.Errorf("Payload[meta]: got %q want %q", pt.Payload["meta"], "data")
	}
}

// Integration tests are guarded with //go:build integration.
// Run with: go test -tags integration -v ./cmd/gibson-backup/internal/store/...
