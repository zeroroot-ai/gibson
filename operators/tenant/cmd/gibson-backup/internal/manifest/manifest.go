// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package manifest defines the per-backup manifest written to S3 as
// <bucket>/<tenant>/<backup-id>/manifest.json.
//
// The manifest records the blob paths, sizes, checksums, and schema version
// for each store included in a backup so that restore and verify operations
// have everything they need without scanning the bucket.
package manifest

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// SchemaVersion is incremented when the manifest structure changes in a
// backwards-incompatible way. Restore and verify implementations must reject
// manifests whose SchemaVersion is higher than what they understand.
const SchemaVersion = 1

// StoreName identifies which per-tenant store a blob belongs to.
type StoreName string

const (
	StorePostgres StoreName = "postgres"
	StoreNeo4j    StoreName = "neo4j"
	StoreRedis    StoreName = "redis"
	StoreVector   StoreName = "vector"
)

// AllStores is the canonical ordered list of stores included in a full backup.
var AllStores = []StoreName{StorePostgres, StoreNeo4j, StoreRedis, StoreVector}

// BlobEntry describes a single encrypted backup file stored in S3.
type BlobEntry struct {
	// Store is the name of the store this blob belongs to.
	Store StoreName `json:"store"`

	// Path is the S3 object key (relative to the bucket root) where the
	// encrypted blob is stored.
	Path string `json:"path"`

	// SizeBytes is the total byte length of the encrypted blob (including
	// the wrapped DEK prefix, GCM nonce, and ciphertext).
	SizeBytes int64 `json:"size_bytes"`

	// SHA256 is the hex-encoded SHA-256 of the encrypted blob.
	SHA256 string `json:"sha256"`

	// SchemaVersion is the schema version of the store at the time of backup.
	// For Postgres this is the golang-migrate version number; for Neo4j it
	// is the migration file count; for Redis and Vector it is 0 (no schema).
	SchemaVersion int64 `json:"schema_version"`
}

// Manifest is the top-level document written to manifest.json.
type Manifest struct {
	// SchemaVersion is the manifest format version (see SchemaVersion const).
	SchemaVersion int `json:"schema_version"`

	// BackupID is the timestamp-derived unique identifier for this backup,
	// formatted as RFC3339Nano with colons replaced by hyphens for S3 key safety.
	BackupID string `json:"backup_id"`

	// TenantID is the tenant whose data this backup contains.
	TenantID string `json:"tenant_id"`

	// CreatedAt is the UTC time the backup was initiated.
	CreatedAt time.Time `json:"created_at"`

	// Note is an optional human-readable label attached at backup time.
	Note string `json:"note,omitempty"`

	// Blobs lists each store's backup blob descriptor in provisioning order.
	Blobs []BlobEntry `json:"blobs"`
}

// BlobPath returns the canonical S3 object key for a store's backup blob under
// the given tenant and backup ID prefix.
//
//	<tenant>/<backup-id>/<store>.enc
func BlobPath(tenantID, backupID string, store StoreName) string {
	return fmt.Sprintf("%s/%s/%s.enc", tenantID, backupID, store)
}

// ManifestPath returns the canonical S3 object key for the manifest document.
//
//	<tenant>/<backup-id>/manifest.json
func ManifestPath(tenantID, backupID string) string {
	return fmt.Sprintf("%s/%s/manifest.json", tenantID, backupID)
}

// Encode serialises m to JSON and writes it to w.
func Encode(w io.Writer, m *Manifest) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return fmt.Errorf("manifest: encode: %w", err)
	}
	return nil
}

// Decode deserialises a Manifest from r.
func Decode(r io.Reader) (*Manifest, error) {
	var m Manifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: decode: %w", err)
	}
	if m.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("manifest: unsupported schema version %d (max %d)", m.SchemaVersion, SchemaVersion)
	}
	return &m, nil
}

// BackupIDFromTime formats t as a safe S3 path component that sorts
// chronologically. Colons in RFC3339Nano are replaced with hyphens.
func BackupIDFromTime(t time.Time) string {
	s := t.UTC().Format(time.RFC3339Nano)
	// Replace colons so the ID is valid in S3 key paths on all platforms.
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			result = append(result, '-')
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}
