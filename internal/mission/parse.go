package mission

import (
	"fmt"

	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

// ParseDefinitionYAML deserializes a YAML mission document into the
// generated proto type `*missionv1.MissionDefinition`. The path is:
// YAML → JSON (sigs.k8s.io/yaml) → proto (protojson.Unmarshal).
//
// Errors from either step are surfaced unwrapped — the underlying
// libraries carry useful line/column / field-path information that
// a custom error type would only obscure.
//
// This replaces the hand-written `ParseMissionDefinition` /
// `ParseError` path that previously lived in this package and
// produced the parallel mirror struct.
//
// Spec: mission-schema-canonicalization Requirement 2.
func ParseDefinitionYAML(b []byte) (*missionv1.MissionDefinition, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("mission definition: empty input")
	}
	jsonBytes, err := yaml.YAMLToJSON(b)
	if err != nil {
		return nil, fmt.Errorf("mission definition: YAML parse: %w", err)
	}
	def := &missionv1.MissionDefinition{}
	opts := protojson.UnmarshalOptions{
		// Reject unknown fields by default — this catches typos at
		// submit time. Future-compat with older daemon versions
		// receiving newer SDK fields is handled at the daemon's
		// gRPC boundary, not here.
		DiscardUnknown: false,
	}
	if err := opts.Unmarshal(jsonBytes, def); err != nil {
		return nil, fmt.Errorf("mission definition: proto unmarshal: %w", err)
	}
	return def, nil
}
