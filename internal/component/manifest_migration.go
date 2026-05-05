// Package component — manifest_migration.go
//
// This file implements wire-format migration of persisted CapabilityManifest
// blobs from the SDK v0.x layout (signature=field 100, signing_key_id=field
// 101) to the SDK v1.0.0 layout (signature=field 200, signing_key_id=field
// 201). Field 100 is reserved platform-wide for
// gibson.graphrag.DiscoveryResult on tool response messages, so the manifest
// signature payload had to be moved out of the reserved range.
//
// The migration parses the protobuf wire format byte-by-byte using
// google.golang.org/protobuf/encoding/protowire. It does NOT depend on the
// generated descriptor — that way it can rewrite blobs that pre-date the
// v1.0.0 schema even after the proto has been regenerated.
//
// The handler is idempotent: blobs that contain only field 200/201 (or
// neither) pass through unchanged. The read-then-rewrite contract is
// preserved by the caller — see registry.go / service.go callsites — so a
// failure to re-emit never corrupts the on-disk representation.
package component

import (
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// legacy signature (length-delimited bytes)
	legacySignatureField = 100
	// legacy signing_key_id (length-delimited string)
	legacySigningKeyIDField = 101
	// new signature field number (v1.0.0)
	newSignatureField = 200
	// new signing_key_id field number (v1.0.0)
	newSigningKeyIDField = 201
)

// ErrMalformedManifest is returned when the input blob cannot be parsed as a
// well-formed protobuf message at the wire-format level.
var ErrMalformedManifest = errors.New("manifest_migration: malformed protobuf blob")

// MigrateManifest detects whether the supplied protobuf blob uses the legacy
// v0.x layout (signature=field 100, signing_key_id=field 101) and rewrites
// it in place to the v1.0.0 layout (200/201). Blobs that already use the new
// layout — or that contain neither legacy nor new tags — pass through
// unchanged.
//
// Returns:
//   - newBlob: the migrated (or pass-through) byte slice. Always non-nil on
//     a nil error.
//   - didMigrate: true if at least one tag was renumbered; emitting code
//     SHOULD persist newBlob back to storage in this case.
//   - err: ErrMalformedManifest (wrapped) if the blob is not parseable.
//
// The function never partial-writes: if any tag in the input cannot be
// parsed, the entire migration aborts with an error and the caller is
// expected to leave the on-disk blob untouched.
func MigrateManifest(blob []byte) ([]byte, bool, error) {
	if len(blob) == 0 {
		// Empty proto is well-formed and trivially up-to-date.
		return blob, false, nil
	}

	out := make([]byte, 0, len(blob))
	didMigrate := false
	migratedFields := make([]int, 0, 2)

	remaining := blob
	for len(remaining) > 0 {
		fieldNum, wireType, tagLen := protowire.ConsumeTag(remaining)
		if tagLen < 0 {
			return nil, false, fmt.Errorf("%w: bad tag at offset %d: %v",
				ErrMalformedManifest, len(blob)-len(remaining), protowire.ParseError(tagLen))
		}

		// Consume the value bytes for this field, by wire type.
		valueLen := protowire.ConsumeFieldValue(fieldNum, wireType, remaining[tagLen:])
		if valueLen < 0 {
			return nil, false, fmt.Errorf("%w: bad value for field %d: %v",
				ErrMalformedManifest, fieldNum, protowire.ParseError(valueLen))
		}

		// Tag + value as one record in the original blob.
		recordLen := tagLen + valueLen
		valueBytes := remaining[tagLen:recordLen]

		// Rewrite legacy fields → new field numbers, preserving the
		// wire-type-specific value bytes verbatim.
		switch int(fieldNum) {
		case legacySignatureField:
			if wireType != protowire.BytesType {
				return nil, false, fmt.Errorf(
					"%w: legacy signature field %d had unexpected wire type %v",
					ErrMalformedManifest, fieldNum, wireType)
			}
			out = protowire.AppendTag(out, newSignatureField, protowire.BytesType)
			out = append(out, valueBytes...)
			didMigrate = true
			migratedFields = append(migratedFields, legacySignatureField)
		case legacySigningKeyIDField:
			if wireType != protowire.BytesType {
				return nil, false, fmt.Errorf(
					"%w: legacy signing_key_id field %d had unexpected wire type %v",
					ErrMalformedManifest, fieldNum, wireType)
			}
			out = protowire.AppendTag(out, newSigningKeyIDField, protowire.BytesType)
			out = append(out, valueBytes...)
			didMigrate = true
			migratedFields = append(migratedFields, legacySigningKeyIDField)
		default:
			// Pass-through: copy the original record unchanged.
			out = append(out, remaining[:recordLen]...)
		}

		remaining = remaining[recordLen:]
	}

	if didMigrate {
		// Structured log event per design: manifest.migrated.
		// One log line per migrated blob (NOT per field), with a list of
		// the field numbers that were renumbered.
		slog.Info("manifest.migrated",
			slog.Any("from_fields", migratedFields),
			slog.String("from_layout", "v0.x (100/101)"),
			slog.String("to_layout", "v1.0.0 (200/201)"),
		)
	}

	return out, didMigrate, nil
}
