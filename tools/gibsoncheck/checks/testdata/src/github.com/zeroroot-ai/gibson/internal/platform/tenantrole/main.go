// Package tenantrole is a testdata stand-in for the real
// internal/platform/tenantrole package: it shadows the real package's
// import path so the guard's package-level exemption can be exercised in
// isolation. It constructs the exact tuple shape the violation fixture
// flags, and it must NOT be flagged here — this IS the one writer.
package tenantrole

import "github.com/zeroroot-ai/gibson/internal/platform/authz"

func writeOwnerTuple(id, t string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: "tenant:" + t}
}
