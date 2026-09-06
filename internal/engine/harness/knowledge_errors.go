// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import "errors"

// ErrKnowledgeUnavailable reports that a knowledge read could not be served, as
// distinct from a read that found nothing.
//
// The daemon deliberately leaves the graphrag seam nil when it has no embedder
// resolver — "unavailable" is a designed state, not an outage. Without a
// matchable sentinel the natural handling of a failed read is to carry on with
// no results, and the agent then reports "no prior findings for this target"
// when the truth is "I could not look". For a security product that is a silent
// false negative.
//
// So a KnowledgeReader method returns this when its seam is absent, and NEVER an
// empty slice with a nil error. The callback service maps it to
// codes.Unavailable so the distinction survives the wire; the SDK mirrors it as
// agent.ErrKnowledgeUnavailable on the far side.
var ErrKnowledgeUnavailable = errors.New("harness: knowledge reads are not available")
