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
// in the Mission.MissionDefinitionJSON field. The snake_case field names
// keep the bytes diffable against the YAML authoring format from which
// the proto was originally parsed.
//
// The proto wire shape uses oneof config for AGENT/TOOL/PLUGIN/CONDITION/
// PARALLEL/JOIN, so node configs nest under a `*_config` envelope (e.g.
// `agent_config: { agent_name: "..." }`). This is intentionally different
// from the legacy flat-mirror JSON shape produced by encoding/json on
// mission.MissionDefinition. Once PR2 of the migration flips writers to
// this helper, MissionDefinitionJSON columns hold protojson-shaped bytes.
//
// Spec: mission-schema-canonicalization (PR1 of mirror→proto migration).
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

// UnmarshalDefinitionJSON parses JSON bytes into a *missionv1.MissionDefinition.
// Accepts both the canonical proto shape (oneof config envelopes) and
// the legacy flat-mirror shape produced by encoding/json on
// mission.MissionDefinition before the mirror→proto migration.
//
// Detection:
//  1. Try protojson with DiscardUnknown=true. Bytes from PR1+ writers
//     and from any legacy bytes that happen to carry no MissionNode
//     entries succeed here.
//  2. If the result has nodes but none of them populated their oneof
//     config envelope, the bytes are flat-mirror shaped (proto's
//     DiscardUnknown silently dropped the unrecognized top-level
//     per-noun fields like `agent_name`). Re-parse via the legacy
//     converter (LegacyMirrorJSONToProto), which walks the mirror
//     struct and emits the proto with config envelopes filled in.
//
// This dual-read path is what lets writers flip to MarshalDefinitionJSON
// without a coordinated storage migration: in-flight Redis / DB rows
// from before the flip remain readable. PR3 removes the legacy fallback
// once the mirror types are deleted.
//
// Spec: mission-schema-canonicalization (PR2 of mirror→proto migration).
func UnmarshalDefinitionJSON(data []byte) (*missionv1.MissionDefinition, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("mission definition: empty JSON")
	}
	def := &missionv1.MissionDefinition{}
	opts := protojson.UnmarshalOptions{
		DiscardUnknown: true,
		AllowPartial:   true,
	}
	if err := opts.Unmarshal(data, def); err == nil && isProtoShaped(def) {
		return def, nil
	}
	return LegacyMirrorJSONToProto(data)
}

// isProtoShaped returns true if the unmarshaled definition either has
// no nodes (proto-shape and mirror-shape are indistinguishable here) or
// has at least one node whose oneof config envelope is populated. The
// legacy mirror shape leaves all oneof fields empty (since the flat
// fields don't map into the envelope), so a node graph with universally
// empty Config strongly indicates the bytes need the legacy fallback.
func isProtoShaped(def *missionv1.MissionDefinition) bool {
	if def == nil || len(def.Nodes) == 0 {
		return true
	}
	for _, node := range def.Nodes {
		if node != nil && node.GetConfig() != nil {
			return true
		}
	}
	return false
}
