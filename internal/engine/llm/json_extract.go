// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llm

import (
	"regexp"
)

// codeBlockPattern matches markdown code blocks with optional language tag
// Captures: (1) optional language, (2) content
var codeBlockPattern = regexp.MustCompile(`(?s)` + "```" + `(\w*)\s*\n(.+?)\n` + "```")
