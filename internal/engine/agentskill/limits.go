// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentskill

// The size limits of a published Agent Skill folder. This file is the one
// place that holds them. A folder over a limit is refused. The daemon never
// truncates a file or a folder (epic gibson#1364, decision of 2026-11-18).
const (
	// MaxBodyBytes is the largest body of SKILL.md, after the frontmatter.
	MaxBodyBytes = 64 << 10
	// MaxFileBytes is the largest single file in the folder.
	MaxFileBytes = 1 << 20
	// MaxFolderBytes is the largest sum of the sizes of all files.
	MaxFolderBytes = 8 << 20
	// MaxFiles is the largest number of files in the folder.
	MaxFiles = 200
)

// The limits of the frontmatter fields, from the Agent Skills format.
const (
	// MaxDescriptionLen is the longest description, in characters.
	MaxDescriptionLen = 1024
	// MaxCompatibilityLen is the longest compatibility text, in characters.
	MaxCompatibilityLen = 500
)
