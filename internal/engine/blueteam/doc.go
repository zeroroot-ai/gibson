// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package blueteam holds the pure reads behind the blue team console
// (gibson#1498, #1499, #1500): the rank of the findings that are not
// `verified`, the actions of the agents by grant and by grantor, and the items
// that wait on a person. Each function takes the facts as arguments and reads
// no clock and no store, so a test and a replay give the same answer.
package blueteam
