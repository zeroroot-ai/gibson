// Package other proves the cypheridentifier analyzer is scoped to exactly
// github.com/zeroroot-ai/gibson/internal/engine/graphrag, not any package
// nested under it. This package has the exact violation shape
// violation.go's rawSprintfViolation is flagged for, and no `want` comment:
// a different package (this one has no cypherFrag type at all, mirroring
// internal/engine/graphrag/engine, which has its own unrelated write-path
// sanitiser) is out of reach by construction, not merely unflagged by scope.
package other

import "fmt"

func rawSprintfOutOfScope(nodeType string) string {
	return fmt.Sprintf("MATCH (n:%s)", nodeType)
}
