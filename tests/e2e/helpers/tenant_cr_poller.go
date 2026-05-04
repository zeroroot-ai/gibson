//go:build e2e
// +build e2e

// Package helpers provides test helper primitives for the signup full-chain
// e2e test suite.  Each file in this package has a single, focused interface:
//
//   - tenant_cr_poller.go — Tenant CR polling and condition inspection
//   - fga_client.go       — OpenFGA HTTP API helpers
//   - zitadel_client.go   — Zitadel admin API helpers
//   - daemon_log_tailer.go — daemon identity-debug log streaming
//   - cluster_setup.go    — kubeconfig discovery + idempotent cleanup
//
// All functions accept context.Context as the first argument.
// None use raw time.Sleep without a deadline+predicate.
// All are runnable against a mock dynamic.Interface for unit testing.
package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
)

// TenantCondition holds a single condition from a Tenant CR's .status.conditions
// list.  The field names match the standard Kubernetes condition convention:
// Type, Status, Reason, Message.
type TenantCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`  // "True" | "False" | "Unknown"
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// tenantGVR is the GroupVersionResource for the Tenant CRD.
// The actual deployed group is gibson.zero-day.ai/v1alpha1 (legacy naming;
// migration to gibson.zero-day.ai is tracked separately — do not rename
// without a CRD storage migration plan).
// Requirement: R3.5 (Go orchestrators target actual CRD group).
var tenantGVR = schema.GroupVersionResource{
	Group:    "gibson.zero-day.ai",
	Version:  "v1alpha1",
	Resource: "tenants",
}

// LatestConditions fetches the current condition list from the named Tenant CR.
// It uses the dynamic client so it works against a real cluster AND against a
// fake.NewSimpleDynamicClient in unit tests.
//
// Returns an empty slice (not an error) if .status.conditions is missing — a
// CR that has never transitioned has no conditions yet.
func LatestConditions(ctx context.Context, client dynamic.Interface, slug string) ([]TenantCondition, error) {
	obj, err := client.Resource(tenantGVR).Get(ctx, slug, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("tenant_cr_poller: get Tenant %q: %w", slug, err)
	}

	// Navigate: .status.conditions
	statusRaw, ok := obj.Object["status"]
	if !ok {
		return nil, nil // CR exists but no status yet
	}
	statusMap, ok := statusRaw.(map[string]interface{})
	if !ok {
		return nil, nil
	}
	condsRaw, ok := statusMap["conditions"]
	if !ok {
		return nil, nil // no conditions populated yet
	}

	// Re-marshal to []TenantCondition via JSON round-trip (the simplest and most
	// robust way to handle the unstructured → typed conversion without reflection).
	b, err := json.Marshal(condsRaw)
	if err != nil {
		return nil, fmt.Errorf("tenant_cr_poller: marshal conditions: %w", err)
	}
	var conds []TenantCondition
	if err := json.Unmarshal(b, &conds); err != nil {
		return nil, fmt.Errorf("tenant_cr_poller: unmarshal conditions: %w", err)
	}
	return conds, nil
}

// LatestPhase returns the .status.phase field of the named Tenant CR.
// Returns ("", nil) if the CR exists but has no phase yet.
func LatestPhase(ctx context.Context, client dynamic.Interface, slug string) (string, error) {
	obj, err := client.Resource(tenantGVR).Get(ctx, slug, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("tenant_cr_poller: get Tenant %q: %w", slug, err)
	}
	statusRaw, ok := obj.Object["status"]
	if !ok {
		return "", nil
	}
	statusMap, ok := statusRaw.(map[string]interface{})
	if !ok {
		return "", nil
	}
	phase, _ := statusMap["phase"].(string)
	return phase, nil
}

// WaitForTenantPhase polls the Tenant CR for the named slug until its
// .status.phase equals wantPhase, or the context deadline is reached.
//
// On success: returns nil.
// On timeout / ctx cancel: returns a descriptive error that includes the
// full condition list (every type/status/reason/message quartet) — this is
// the information block that appears in the CI failure log and maps to the
// B-catalog entries.
//
// The poll interval is 2 seconds, chosen to be fast enough for 60-second saga
// completion while keeping API server load low.  It uses
// wait.PollUntilContextTimeout — no raw time.Sleep.
//
// Requirements: R1.2, R1.3.  Bug catalog: general saga timeout.
func WaitForTenantPhase(ctx context.Context, client dynamic.Interface, slug, wantPhase string, deadline time.Duration) error {
	pollCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	var lastConds []TenantCondition
	var lastPhase string

	err := wait.PollUntilContextTimeout(pollCtx, 2*time.Second, deadline, true /* immediate first poll */,
		func(ctx context.Context) (done bool, err error) {
			phase, pErr := LatestPhase(ctx, client, slug)
			if pErr != nil {
				// Don't abort: CR may not be visible yet right after signup.
				lastPhase = fmt.Sprintf("(error: %v)", pErr)
				return false, nil
			}
			lastPhase = phase

			conds, cErr := LatestConditions(ctx, client, slug)
			if cErr == nil {
				lastConds = conds
			}

			return phase == wantPhase, nil
		},
	)
	if err != nil {
		// Build a human-readable condition dump for the failure message.
		condDump := formatConditions(lastConds)
		return fmt.Errorf(
			"WaitForTenantPhase: Tenant %q did not reach phase %q within %s "+
				"(last phase: %q)\n"+
				"Condition dump:\n%s\n"+
				"Bug catalog hint: if EntitlementsReconciled is False, see B6/B7/B9/B11/B14/B16; "+
				"if FGAReady is False, see B8/B9; if ZitadelOrgReady is False, see B4/B6; "+
				"if NamespaceProvisioned is False, see B10",
			slug, wantPhase, deadline, lastPhase, condDump,
		)
	}
	return nil
}

// AssertConditionTrue checks that the named condition in the Tenant CR has
// status "True".  If not, it returns a catalog-mapped error.
//
// condName is one of the 10 required conditions from R1.4:
// NamespaceProvisioned, LangfuseReady, StripeReady, BillingPending,
// ZitadelOrgReady, FGAReady, RedisReady, Neo4jReady, EntitlementsReconciled,
// Ready.
func AssertConditionTrue(t interface{ Fatalf(string, ...interface{}) },
	conds []TenantCondition, condName string) {

	for _, c := range conds {
		if c.Type == condName {
			if c.Status == "True" {
				return
			}
			t.Fatalf(
				"assert condition %s=True: got Status=%q Reason=%q Message=%q\n"+
					"Bug catalog: %s",
				condName, c.Status, c.Reason, c.Message,
				condCatalogHint(condName),
			)
			return
		}
	}
	t.Fatalf(
		"assert condition %s=True: condition NOT FOUND in Tenant CR (conditions present: %s)\n"+
			"Bug catalog: %s",
		condName, condNames(conds), condCatalogHint(condName),
	)
}

// formatConditions renders conditions as a numbered list for failure messages.
func formatConditions(conds []TenantCondition) string {
	if len(conds) == 0 {
		return "  (no conditions)"
	}
	var sb strings.Builder
	for i, c := range conds {
		fmt.Fprintf(&sb, "  [%d] type=%s status=%s reason=%s message=%s\n",
			i+1, c.Type, c.Status, c.Reason, c.Message)
	}
	return sb.String()
}

// condNames returns a comma-separated list of condition type names for error
// messages when a condition is missing.
func condNames(conds []TenantCondition) string {
	names := make([]string, len(conds))
	for i, c := range conds {
		names[i] = c.Type
	}
	return strings.Join(names, ", ")
}

// condCatalogHint maps a condition name to the relevant B-catalog entries so
// failure messages point engineers directly to the right design.md section.
func condCatalogHint(condName string) string {
	hints := map[string]string{
		"NamespaceProvisioned":   "B10 (Envoy daemon cluster name → no healthy upstream → operator can't call daemon)",
		"LangfuseReady":          "general: Langfuse pod availability",
		"StripeReady":            "general: Stripe API credentials",
		"BillingPending":         "general: billing saga step",
		"ZitadelOrgReady":        "B4 (jwt_issuer missing → Zitadel rejects token), B6 (SPIFFE prefix in user ID)",
		"FGAReady":               "B8 (fga-init silent error), B9 (wrong FGA endpoint in ext-authz)",
		"RedisReady":             "general: Redis connectivity",
		"Neo4jReady":             "general: Neo4j connectivity",
		"EntitlementsReconciled": "B6 (SPIFFE user prefix), B7 (wrong FGA relation), B9 (ext-authz FGA addr), B11/B14 (mTLS mismatch), B16 (headers stripped)",
		"Ready":                  "all prior conditions must be True first",
	}
	if h, ok := hints[condName]; ok {
		return h
	}
	return "see design.md § Failure Mode Catalog"
}
