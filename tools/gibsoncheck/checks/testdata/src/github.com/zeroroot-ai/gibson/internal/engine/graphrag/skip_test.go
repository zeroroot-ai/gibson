package graphrag

import "fmt"

// testFixtureRawSprintf stands in for a test that builds a throwaway
// Cypher-shaped string to seed a mock graph client. Test files are exempt —
// that is not the data plane this analyzer protects — so this call must
// produce NO diagnostic even though it is the exact shape violation.go's
// rawSprintfViolation is flagged for. No `want` comment here means
// analysistest fails if the analyzer stops skipping _test.go files.
func testFixtureRawSprintf(nodeType string) string {
	return fmt.Sprintf("MATCH (n:%s)", nodeType)
}
