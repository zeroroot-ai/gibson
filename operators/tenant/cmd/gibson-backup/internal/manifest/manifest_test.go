/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package manifest_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup/internal/manifest"
)

func TestRoundtrip(t *testing.T) {
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	orig := &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		BackupID:      manifest.BackupIDFromTime(now),
		TenantID:      "acme",
		CreatedAt:     now,
		Note:          "daily backup",
		Blobs: []manifest.BlobEntry{
			{
				Store:         manifest.StorePostgres,
				Path:          manifest.BlobPath("acme", "2026-04-26T12-00-00Z", manifest.StorePostgres),
				SizeBytes:     12345,
				SHA256:        "abc123",
				SchemaVersion: 7,
			},
			{
				Store:         manifest.StoreNeo4j,
				Path:          manifest.BlobPath("acme", "2026-04-26T12-00-00Z", manifest.StoreNeo4j),
				SizeBytes:     5678,
				SHA256:        "def456",
				SchemaVersion: 3,
			},
			{
				Store:         manifest.StoreRedis,
				Path:          manifest.BlobPath("acme", "2026-04-26T12-00-00Z", manifest.StoreRedis),
				SizeBytes:     999,
				SHA256:        "ghi789",
				SchemaVersion: 0,
			},
			{
				Store:         manifest.StoreVector,
				Path:          manifest.BlobPath("acme", "2026-04-26T12-00-00Z", manifest.StoreVector),
				SizeBytes:     11111,
				SHA256:        "jkl012",
				SchemaVersion: 0,
			},
		},
	}

	var buf bytes.Buffer
	if err := manifest.Encode(&buf, orig); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, err := manifest.Decode(&buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got.TenantID != orig.TenantID {
		t.Errorf("TenantID: got %q, want %q", got.TenantID, orig.TenantID)
	}
	if got.BackupID != orig.BackupID {
		t.Errorf("BackupID: got %q, want %q", got.BackupID, orig.BackupID)
	}
	if got.Note != orig.Note {
		t.Errorf("Note: got %q, want %q", got.Note, orig.Note)
	}
	if got.SchemaVersion != manifest.SchemaVersion {
		t.Errorf("SchemaVersion: got %d, want %d", got.SchemaVersion, manifest.SchemaVersion)
	}
	if len(got.Blobs) != len(orig.Blobs) {
		t.Fatalf("Blobs len: got %d, want %d", len(got.Blobs), len(orig.Blobs))
	}
	for i, b := range got.Blobs {
		ob := orig.Blobs[i]
		if b.Store != ob.Store {
			t.Errorf("Blobs[%d].Store: got %q, want %q", i, b.Store, ob.Store)
		}
		if b.Path != ob.Path {
			t.Errorf("Blobs[%d].Path: got %q, want %q", i, b.Path, ob.Path)
		}
		if b.SizeBytes != ob.SizeBytes {
			t.Errorf("Blobs[%d].SizeBytes: got %d, want %d", i, b.SizeBytes, ob.SizeBytes)
		}
		if b.SHA256 != ob.SHA256 {
			t.Errorf("Blobs[%d].SHA256: got %q, want %q", i, b.SHA256, ob.SHA256)
		}
		if b.SchemaVersion != ob.SchemaVersion {
			t.Errorf("Blobs[%d].SchemaVersion: got %d, want %d", i, b.SchemaVersion, ob.SchemaVersion)
		}
	}
}

func TestDecodeUnsupportedSchemaVersion(t *testing.T) {
	src := `{"schema_version": 9999, "backup_id": "x", "tenant_id": "t", "blobs": []}`
	_, err := manifest.Decode(strings.NewReader(src))
	if err == nil {
		t.Fatal("expected error for unsupported schema version, got nil")
	}
}

func TestBackupIDFromTime(t *testing.T) {
	ts := time.Date(2026, 4, 26, 15, 30, 45, 123456789, time.UTC)
	id := manifest.BackupIDFromTime(ts)
	if strings.Contains(id, ":") {
		t.Errorf("BackupID contains colon, unsafe for S3 keys: %q", id)
	}
	// Should start with the date.
	if !strings.HasPrefix(id, "2026-04-26T") {
		t.Errorf("BackupID unexpected format: %q", id)
	}
}

func TestBlobPaths(t *testing.T) {
	p := manifest.BlobPath("acme", "2026-04-26T12-00-00Z", manifest.StorePostgres)
	if p != "acme/2026-04-26T12-00-00Z/postgres.enc" {
		t.Errorf("unexpected BlobPath: %q", p)
	}
	m := manifest.ManifestPath("acme", "2026-04-26T12-00-00Z")
	if m != "acme/2026-04-26T12-00-00Z/manifest.json" {
		t.Errorf("unexpected ManifestPath: %q", m)
	}
}
