package component

import (
	"bytes"
	"errors"
	"testing"

	manifestpb "github.com/zero-day-ai/sdk/api/gen/gibson/manifest/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// buildLegacyBlob hand-rolls a CapabilityManifest blob using the v0.x layout
// (signature=field 100, signing_key_id=field 101). We can't use the
// generated proto types because they no longer include those field numbers
// — that's the whole point of the migration.
func buildLegacyBlob(t *testing.T, sig []byte, kid string) []byte {
	t.Helper()

	var buf []byte
	// manifest_id (field 1, string) — sentinel so we can prove pass-through.
	buf = protowire.AppendTag(buf, 1, protowire.BytesType)
	buf = protowire.AppendString(buf, "manifest-legacy-1")
	// signature (legacy field 100, bytes)
	buf = protowire.AppendTag(buf, legacySignatureField, protowire.BytesType)
	buf = protowire.AppendBytes(buf, sig)
	// signing_key_id (legacy field 101, string)
	buf = protowire.AppendTag(buf, legacySigningKeyIDField, protowire.BytesType)
	buf = protowire.AppendString(buf, kid)
	return buf
}

func TestMigrateManifest_LegacyToNew(t *testing.T) {
	sig := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	kid := "kid-foo"

	legacy := buildLegacyBlob(t, sig, kid)

	migrated, didMigrate, err := MigrateManifest(legacy)
	if err != nil {
		t.Fatalf("MigrateManifest returned error on legacy blob: %v", err)
	}
	if !didMigrate {
		t.Fatalf("expected didMigrate=true on legacy blob")
	}

	// The migrated blob must parse cleanly with the v1.0.0 descriptor.
	got := &manifestpb.CapabilityManifest{}
	if err := proto.Unmarshal(migrated, got); err != nil {
		t.Fatalf("migrated blob did not parse with v1.0.0 descriptor: %v", err)
	}
	if got.ManifestId != "manifest-legacy-1" {
		t.Errorf("manifest_id pass-through failed: got %q", got.ManifestId)
	}
	if !bytes.Equal(got.Signature, sig) {
		t.Errorf("signature mismatch: got %x want %x", got.Signature, sig)
	}
	if got.SigningKeyId != kid {
		t.Errorf("signing_key_id mismatch: got %q want %q", got.SigningKeyId, kid)
	}

	// The migrated blob must NOT contain the legacy field numbers anywhere.
	if containsFieldNumber(t, migrated, legacySignatureField) {
		t.Errorf("migrated blob still contains legacy field 100")
	}
	if containsFieldNumber(t, migrated, legacySigningKeyIDField) {
		t.Errorf("migrated blob still contains legacy field 101")
	}
	if !containsFieldNumber(t, migrated, newSignatureField) {
		t.Errorf("migrated blob missing new field 200")
	}
	if !containsFieldNumber(t, migrated, newSigningKeyIDField) {
		t.Errorf("migrated blob missing new field 201")
	}
}

func TestMigrateManifest_NewIsIdempotent(t *testing.T) {
	// New-format blob built via the v1.0.0 generated proto types.
	src := &manifestpb.CapabilityManifest{
		ManifestId:   "manifest-new-1",
		Signature:    []byte{0x01, 0x02, 0x03},
		SigningKeyId: "kid-bar",
	}
	blob, err := proto.Marshal(src)
	if err != nil {
		t.Fatalf("Marshal v1.0.0 manifest: %v", err)
	}

	migrated, didMigrate, err := MigrateManifest(blob)
	if err != nil {
		t.Fatalf("MigrateManifest returned error on new blob: %v", err)
	}
	if didMigrate {
		t.Errorf("expected didMigrate=false on new-format blob")
	}
	if !bytes.Equal(migrated, blob) {
		t.Errorf("new-format blob should pass through byte-for-byte")
	}
}

func TestMigrateManifest_Empty(t *testing.T) {
	migrated, didMigrate, err := MigrateManifest(nil)
	if err != nil {
		t.Fatalf("MigrateManifest returned error on nil: %v", err)
	}
	if didMigrate {
		t.Errorf("expected didMigrate=false on empty blob")
	}
	if len(migrated) != 0 {
		t.Errorf("expected empty output, got %d bytes", len(migrated))
	}
}

func TestMigrateManifest_Malformed(t *testing.T) {
	// Truncated tag: a single byte that has the continuation bit set, so
	// the varint can't be parsed.
	bad := []byte{0x80}
	_, _, err := MigrateManifest(bad)
	if err == nil {
		t.Fatalf("expected error on malformed blob, got nil")
	}
	if !errors.Is(err, ErrMalformedManifest) {
		t.Errorf("expected ErrMalformedManifest, got %v", err)
	}
}

func TestMigrateManifest_LegacySignatureWrongWireType(t *testing.T) {
	// Encode field 100 as varint (wire type 0) instead of bytes (wire type 2).
	// This should fail loud rather than silently corrupt the migration.
	var buf []byte
	buf = protowire.AppendTag(buf, legacySignatureField, protowire.VarintType)
	buf = protowire.AppendVarint(buf, 42)

	_, _, err := MigrateManifest(buf)
	if err == nil {
		t.Fatalf("expected error on field 100 with wrong wire type")
	}
	if !errors.Is(err, ErrMalformedManifest) {
		t.Errorf("expected ErrMalformedManifest, got %v", err)
	}
}

// containsFieldNumber walks the wire format and returns true if any tag
// matches the supplied field number.
func containsFieldNumber(t *testing.T, blob []byte, want int) bool {
	t.Helper()
	rem := blob
	for len(rem) > 0 {
		fieldNum, wireType, tagLen := protowire.ConsumeTag(rem)
		if tagLen < 0 {
			return false
		}
		if int(fieldNum) == want {
			return true
		}
		valueLen := protowire.ConsumeFieldValue(fieldNum, wireType, rem[tagLen:])
		if valueLen < 0 {
			return false
		}
		rem = rem[tagLen+valueLen:]
	}
	return false
}
