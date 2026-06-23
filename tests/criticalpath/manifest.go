// Package criticalpath declares the named, mandatory critical-path tests that
// the integration lane must always carry (gibson#795, E3 / QUALITY-BARS §4
// Tier 3), and guards their existence.
//
// QUALITY-BARS §4 Tier 3 names five critical paths that must each have a
// present, green integration test:
//
//  1. auth-chain          — JWT → ext-authz → FGA → handler
//  2. per-tenant isolation — write as tenant A, assert tenant B sees nothing
//                            (guards the predicate-leak / IDOR class)
//  3. tenant-provision saga — step idempotency + rollback/teardown
//  4. mission-run          — a mission is driven through the engine
//  5. entitlements/billing-bypass — on-prem entitlement bypass + operator bypass
//
// Rather than re-implement coverage that already exists, this manifest pins the
// concrete test functions that cover each path. The guard test
// (manifest_test.go) is a pure-unit AST check — no Docker, no infra — that
// fails CI if any pinned test is deleted or renamed. So the critical-path suite
// can never silently regress, and the integration lane that runs these tests
// (.github/workflows/integration.yml) has a stable, enumerable contract.
package criticalpath

// CoveringTest pins one test function, located by the repo-relative directory
// of the package that declares it. Dir is used (not just the bare name) so a
// rename that moves the test out of its subsystem is also caught.
type CoveringTest struct {
	Dir  string // repo-relative package directory, e.g. "tests/integration"
	Func string // exact test function name, e.g. "TestPerTenantMissionIsolation_TwoTenants"
}

// CriticalPath is one of the five mandatory Tier-3 paths and the tests that
// keep it honest.
type CriticalPath struct {
	Name    string
	Purpose string
	Tests   []CoveringTest
}

// Manifest is the authoritative list. Every entry's Tests must exist; the guard
// enforces it. To add coverage, add a CoveringTest. To retire one, you must
// edit this file in the same change — which is the point.
var Manifest = []CriticalPath{
	{
		Name:    "auth-chain",
		Purpose: "JWT → ext-authz → FGA → handler: identity class and FGA relation are enforced end to end.",
		Tests: []CoveringTest{
			// ext-authz's FGA decision: identity-class bitfield + deny-all.
			{Dir: "internal/server/extauthz/fga", Func: "TestCheck_ZeroBitfieldDenyAll"},
			{Dir: "internal/server/extauthz/fga", Func: "TestCheck_UserVsUserOnlyRPC"},
			// Handler end of the chain: cross-principal access is denied.
			{Dir: "tests/integration", Func: "TestGetUserProfile_CrossUser_Denied"},
		},
	},
	{
		Name:    "per-tenant-isolation",
		Purpose: "Write as tenant A, assert tenant B sees nothing. Guards the predicate-leak / IDOR class.",
		Tests: []CoveringTest{
			{Dir: "tests/integration", Func: "TestPerTenantMissionIsolation_TwoTenants"},
			{Dir: "tests/integration", Func: "TestPerTenantMissionIsolation_CrossTenantGetReturnsNotFound"},
			{Dir: "tests/integration", Func: "TestPerTenantFindingIDOR_CrossTenantGetReturnsNotFound"},
		},
	},
	{
		Name:    "tenant-provision-saga",
		Purpose: "Provisioning saga steps are idempotent on re-run and have a rollback/teardown path.",
		Tests: []CoveringTest{
			{Dir: "operators/tenant/internal/saga/flows", Func: "TestInitRedisStep_Idempotent"},
			{Dir: "operators/tenant/internal/saga/flows", Func: "TestFinalBackupStep_IdempotentCompletedBackup"},
			{Dir: "operators/tenant/internal/saga/flows", Func: "TestEnrollmentRevocationSteps_RegistryContract"},
		},
	},
	{
		Name:    "mission-run",
		Purpose: "Running missions are recovered and fanned out per tenant after a restart.",
		Tests: []CoveringTest{
			{Dir: "tests/integration", Func: "TestRecoverRunningMissions_PerTenantFanOut"},
		},
	},
	{
		Name:    "entitlements-billing-bypass",
		Purpose: "Entitlement classification and the operator bypass behave as specified (on-prem billing is bypassable).",
		Tests: []CoveringTest{
			{Dir: "internal/server/daemon/api", Func: "TestClassifyRelationAction"},
			{Dir: "internal/server/daemon/api", Func: "TestGetCheckpoint_OperatorBypassesRedaction"},
		},
	},
}
