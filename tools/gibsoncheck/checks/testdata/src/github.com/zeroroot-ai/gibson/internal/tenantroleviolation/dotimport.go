package tenantroleviolation

import (
	. "fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// N14 — a dot-imported fmt.Sprintf called bare (no selector). call.Fun here
// is a *ast.Ident, not a *ast.SelectorExpr, so isFmtSprintfCall's own
// selector check never fires — this exercises isTenantObjectFuncCall's
// bare-Ident branch instead, resolving straight to the real fmt.Sprintf
// *types.Func (which is not in tenantObjectFuncs, so this is correctly not
// flagged). This is also a real, documented limitation: a dot-imported
// Sprintf bypasses the tenant-prefix Sprintf detection entirely. No
// converted code in this repo dot-imports fmt.
func writeUsingADotImportedSprintf(id, t string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: Sprintf("tenant:%s", t)}
}
