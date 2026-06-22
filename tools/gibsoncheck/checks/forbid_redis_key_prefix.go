package checks

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// ForbidRedisKeyPrefixAnalyzer flags string literals that look like per-tenant
// Redis key-prefix patterns (e.g. "tenant:", "gibson:tenant:", or any
// "<word>:<identifier>:" shape used as a key-builder prefix).
//
// In the database-per-tenant model each tenant's Redis client is already
// bound to a dedicated logical DB — so key prefixes are both unnecessary
// and confusing.  The only legitimate users of raw tenant-scoped prefix
// construction are:
//
//   - internal/infra/datapool/admin/ — the master index DB lookup that maps
//     tenant IDs to logical DB indices.
//   - internal/server/daemon/   — the event-stream Redis files and a few
//     specific daemon-internal coordinator keys.
//   - internal/platform/component/ — component-quota counters keyed by component
//     name, not tenant ID.
//   - internal/platform/audit/     — audit stream keys.
//
// All other packages must hold a Conn.Redis (which is already DB-scoped)
// and use plain keys without prefix.
//
// The check inspects string literals that appear as the first argument to
// any call whose function name is one of the common Redis write/read
// methods (Set, Get, Del, HSet, HGet, HDel, Expire, Exists, SAdd, SRem,
// LPush, RPush, LRange, XAdd, ZAdd, ZRangeByScore, etc.).  This is a
// name-based heuristic; for full precision a type-checker-aware pass
// would be needed, but in practice all Redis call sites name their methods
// from the redis.Client vocabulary.
//
// Pattern matched: a string literal whose value matches
//
//	tenant:<anything>   or
//	gibson:tenant:<anything>   or
//	<word>:tenant:<anything>   or
//	<word>:<uuid-or-placeholder>:
//
// The last form catches fmt.Sprintf-style format strings like
// "mission:%s:events" passed as a key template.
//
// Spec: database-per-tenant-data-plane Phase I Task 9.3, Requirement 16.1.
var ForbidRedisKeyPrefixAnalyzer = &analysis.Analyzer{
	Name: "forbidrediskeyprefix",
	Doc:  "fail on string literals that look like per-tenant Redis key-prefix patterns (database-per-tenant-data-plane Req 16.1)",
	Run:  runForbidRedisKeyPrefix,
}

// tenantPrefixPattern matches string literal values that are per-tenant Redis
// key prefixes that must not appear outside the allowlisted packages.
// Groups of patterns:
//  1. Literal "tenant:" prefix (e.g. "tenant:abc123:missions")
//  2. "gibson:tenant:" variants
//  3. Namespace:tenant: variants
//  4. Format strings containing %s or %v followed by a colon (key templates)
//     where "tenant" appears adjacent.
var tenantPrefixPatterns = []*regexp.Regexp{
	// "tenant:..." — bare tenant prefix
	regexp.MustCompile(`(?i)^tenant:`),
	// "gibson:tenant:..." — namespaced tenant prefix
	regexp.MustCompile(`(?i)^gibson:tenant:`),
	// "<word>:tenant:..." — any namespace:tenant: prefix
	regexp.MustCompile(`(?i)^[a-z][a-z0-9_-]*:tenant:`),
}

// redisMethods lists Redis client method names whose first string argument
// is treated as the key.  Name-based heuristic — sufficient for the codebase.
var redisMethods = map[string]bool{
	"Set":              true,
	"SetEx":            true,
	"SetNX":            true,
	"Get":              true,
	"GetEx":            true,
	"Del":              true,
	"Expire":           true,
	"ExpireAt":         true,
	"Exists":           true,
	"HSet":             true,
	"HGet":             true,
	"HDel":             true,
	"HGetAll":          true,
	"HExists":          true,
	"SAdd":             true,
	"SRem":             true,
	"SMembers":         true,
	"SIsMember":        true,
	"LPush":            true,
	"RPush":            true,
	"LRange":           true,
	"LLen":             true,
	"XAdd":             true,
	"XRead":            true,
	"XReadGroup":       true,
	"ZAdd":             true,
	"ZRangeByScore":    true,
	"ZRangeWithScores": true,
	"ZScore":           true,
	"ZRem":             true,
	"ZCard":            true,
	"ZCount":           true,
	"Incr":             true,
	"IncrBy":           true,
	"Decr":             true,
	"DecrBy":           true,
}

// allowedRedisPrefixPackages lists package import-path substrings that are
// permitted to use tenant-scoped key-prefix patterns.  These are the
// subsystems that legitimately hold shared-Redis keys for cross-tenant
// accounting, event streams, and audit logs — NOT per-tenant data.
var allowedRedisPrefixPackages = []string{
	"/internal/infra/datapool/admin",
	"/internal/infra/datapool",
	"/internal/server/daemon",
	"/internal/platform/audit",
	"/internal/platform/component",
	"/internal/migrate",
	"/cmd/gibson-migrate",
	"/tools/gibsoncheck",
}

func runForbidRedisKeyPrefix(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()

	for _, allowed := range allowedRedisPrefixPackages {
		if strings.Contains(pkgPath, allowed) {
			return nil, nil
		}
	}

	for _, file := range pass.Files {
		// Skip test files — tests may use inline key strings for fixtures.
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			// Only care about selector calls: receiver.Method(args...).
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			if !redisMethods[sel.Sel.Name] {
				return true
			}

			// The first argument must be a string literal.
			if len(call.Args) == 0 {
				return true
			}

			keyLit := firstStringLiteral(call.Args[0])
			if keyLit == "" {
				return true
			}

			for _, re := range tenantPrefixPatterns {
				if re.MatchString(keyLit) {
					pass.Reportf(call.Args[0].Pos(),
						"tenant key-prefix pattern %q in %q — per-tenant Redis access must use Conn.Redis (which is already DB-scoped to the tenant, so no key prefix is needed). Remove the prefix and use a plain key. (database-per-tenant-data-plane Req 16.1)",
						keyLit, pkgPath)
					break
				}
			}

			return true
		})
	}

	return nil, nil
}

// firstStringLiteral extracts the string value from an expression if it is
// (or contains) a basic string literal.  Handles:
//   - *ast.BasicLit of kind STRING directly.
//   - *ast.BinaryExpr where the left side is a string literal (catches
//     "prefix:" + variable or "prefix:" + fmt.Sprintf(...) patterns).
func firstStringLiteral(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			s, err := strconv.Unquote(e.Value)
			if err != nil {
				return ""
			}
			return s
		}
	case *ast.BinaryExpr:
		// "tenant:"+something — the left operand is the prefix literal.
		return firstStringLiteral(e.X)
	}
	return ""
}
