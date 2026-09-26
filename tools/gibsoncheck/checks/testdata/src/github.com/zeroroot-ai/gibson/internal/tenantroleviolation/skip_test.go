package tenantroleviolation

import "github.com/zeroroot-ai/gibson/internal/platform/authz"

// writeOwnerTupleDirectlyInATestFile is the exact R1 shape, but in a _test.go
// file. Test files are exempt (a test that seeds a fixture graph is not the
// data plane): this must NOT be flagged, unlike the identical construction
// in main.go.
func writeOwnerTupleDirectlyInATestFile(id, t string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: "tenant:" + t}
}
