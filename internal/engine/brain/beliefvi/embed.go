// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import _ "embed"

// embeddedBaseV1JSON is a byte-for-byte copy of sidecar/belief/models/base-v1.json,
// the OSS-shipped minimal base model (see that package's README). It is
// duplicated here — go:embed cannot reach outside this package's directory
// tree — rather than loaded from a runtime file path, so a self-hosted or
// dev binary built from source needs no external model file to score belief
// at all (ADR-0134: "no belief-sidecar container, no round-trip"). Two
// invariants keep the duplicate honest:
//
//  1. sidecar/belief/models/base-v1.json stays canonical — braintrain and
//     the Python offline tooling (model.py, gen_parity_fixture.py) read it
//     from there, unchanged.
//  2. TestDefaultArtifact_MatchesTheCanonicalPythonSource (embed_test.go)
//     byte-compares this copy against that canonical file, so the two can
//     never silently drift apart.
//
//go:embed models/base-v1.json
var embeddedBaseV1JSON []byte

// DefaultArtifact parses and returns the embedded base-v1 model artifact —
// the model a daemon uses when no GIBSON_BELIEF_MODEL_PATH override names a
// different (e.g. commercial curated) artifact.
func DefaultArtifact() (ModelArtifact, error) {
	return ParseModelArtifact(embeddedBaseV1JSON)
}
