package mission

import (
	"fmt"

	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// MarshalDefinitionJSON serializes a *missionv1.MissionDefinition to JSON
// bytes using protojson with snake_case field names (UseProtoNames=true)
// and zero-value field emission disabled.
//
// This is the canonical wire/storage format for mission definitions used
// in the Mission.MissionDefinitionJSON field and the
// gibson:mission-definitions:* Redis key family. The snake_case field
// names keep the bytes diffable against the YAML authoring format from
// which the proto was originally parsed.
func MarshalDefinitionJSON(def *missionv1.MissionDefinition) ([]byte, error) {
	if def == nil {
		return nil, fmt.Errorf("mission definition: nil input")
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
		AllowPartial:    false,
	}
	b, err := opts.Marshal(def)
	if err != nil {
		return nil, fmt.Errorf("mission definition: protojson marshal: %w", err)
	}
	return b, nil
}

// UnmarshalDefinitionJSON parses canonical proto-shape JSON bytes into a
// *missionv1.MissionDefinition. DiscardUnknown lets the reader outlive
// a slightly newer writer that has added fields; AllowPartial defers
// structural validation to the protovalidate gRPC interceptor.
//
// Pre-PR4 stored bytes in the legacy flat-mirror shape are not handled
// here. Operators with such data run cmd/mission-storage-migrate once
// against their Redis to rewrite them in-place. Dev clusters drop the
// keys (redis-cli FLUSHDB) — pre-revenue posture; no preserved data.
func UnmarshalDefinitionJSON(data []byte) (*missionv1.MissionDefinition, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("mission definition: empty JSON")
	}
	def := &missionv1.MissionDefinition{}
	opts := protojson.UnmarshalOptions{
		DiscardUnknown: true,
		AllowPartial:   true,
	}
	if err := opts.Unmarshal(data, def); err != nil {
		return nil, fmt.Errorf("mission definition: protojson unmarshal: %w", err)
	}
	return def, nil
}
