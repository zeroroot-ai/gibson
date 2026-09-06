// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import "errors"

// errNoWorldSink is returned when a processor is constructed without a World
// sink. It is an error rather than a no-op so that a mis-wired daemon is loud:
// a discovery path that quietly accepts and discards is indistinguishable from
// one that works.
var errNoWorldSink = errors.New("ingest: discovery processor has no World sink")
