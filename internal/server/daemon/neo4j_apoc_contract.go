// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
	"github.com/zeroroot-ai/sdk/auth"
	sdktypes "github.com/zeroroot-ai/sdk/types"
)

// cypherRows runs one read query and returns its rows as column maps. The
// readiness probe below is written against this seam so a fake can stand in
// for a Neo4j server in tests; the daemon passes a session-backed runner.
type cypherRows func(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error)

// errAllowlistUnreadable says the server refused dbms.listConfig, which needs
// admin. The procedure check still stands; the allowlist is unverified, not
// wrong.
var errAllowlistUnreadable = errors.New("allowlist unreadable")

// verifyAPOCContract asks the live Neo4j whether it was provisioned the way
// pkg/platform/dataplane says every Neo4j gibson writes to must be: the
// allowlisted APOC procedures are installed, and the procedure allowlist
// equals Neo4jProcedureAllowlist (gibson#28).
//
// Three provisioners write that contract, the tenant-operator, gibson-migrate
// and the umbrella chart's own Neo4j, and only the first two read the Go
// constants. Nothing at build time binds the chart's copy to them, so the
// daemon checks the server it is about to write to and reports a mismatch
// on readiness, where an install profile that drifted is caught before the
// projector fails at runtime. It also covers a Neo4j a customer provisioned
// by hand, which no chart guard can reach.
//
// A nil return means the contract holds. errAllowlistUnreadable means the
// procedures are present and the allowlist could not be read; the caller
// decides how loud that is.
func verifyAPOCContract(ctx context.Context, run cypherRows) error {
	want := strings.Split(dataplane.Neo4jProcedureAllowlist, ",")
	for i := range want {
		want[i] = strings.TrimSpace(want[i])
	}
	sort.Strings(want)

	rows, err := run(ctx, "SHOW PROCEDURES YIELD name WHERE name IN $names RETURN name", map[string]any{"names": want})
	if err != nil {
		return fmt.Errorf("list APOC procedures: %w", err)
	}
	have := map[string]bool{}
	for _, r := range rows {
		if n, ok := r["name"].(string); ok {
			have[n] = true
		}
	}
	var missing []string
	for _, n := range want {
		if !have[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("APOC procedure(s) %s not installed on this Neo4j: the provisioner did not place the jar (%s -> %s/apoc.jar); the projector's merges would fail",
			strings.Join(missing, ", "), dataplane.APOCCoreJarGlob, dataplane.Neo4jPluginsDir)
	}

	rows, err = run(ctx, "CALL dbms.listConfig('dbms.security.procedures.allowlist') YIELD value RETURN value", nil)
	if err != nil {
		return fmt.Errorf("%w: %w", errAllowlistUnreadable, err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("%w: dbms.listConfig returned no row", errAllowlistUnreadable)
	}
	got, _ := rows[0]["value"].(string)
	gotList := strings.Split(got, ",")
	for i := range gotList {
		gotList[i] = strings.TrimSpace(gotList[i])
	}
	sort.Strings(gotList)
	if strings.Join(gotList, ",") != strings.Join(want, ",") {
		return fmt.Errorf("Neo4j dbms.security.procedures.allowlist is %q, the contract says %q: this Neo4j was provisioned from a copy of the contract that drifted",
			got, dataplane.Neo4jProcedureAllowlist)
	}
	return nil
}

// apocContractCheck is the readiness check that runs verifyAPOCContract
// against the install tenant's Neo4j, the one this daemon's projector writes
// to. Only a verified mismatch degrades readiness. A state that cannot be
// verified yet (no install tenant, pool not up, tenant not provisioned, the
// allowlist unreadable by the tenant user) stays Healthy and says why, so the
// check never removes a pod for a reason the operator cannot act on. A pass
// is sticky: a provisioned Neo4j does not lose its plugins while it runs.
type apocContractCheck struct {
	tenant string
	pool   func() datapool.Pool
	rows   func(neo4j.SessionWithContext) cypherRows
	log    *slog.Logger
	passed atomic.Bool
}

func newAPOCContractCheck(tenant string, pool func() datapool.Pool, log *slog.Logger) *apocContractCheck {
	return &apocContractCheck{tenant: tenant, pool: pool, rows: sessionRows, log: log}
}

func (c *apocContractCheck) status(ctx context.Context) sdktypes.HealthStatus {
	if c.passed.Load() {
		return sdktypes.NewHealthyStatus("Neo4j APOC contract verified on the install tenant's data plane")
	}
	if c.tenant == "" {
		return sdktypes.NewHealthyStatus("Neo4j APOC contract not checked: GIBSON_PLATFORM_TENANT is unset")
	}
	tid, err := auth.NewTenantID(c.tenant)
	if err != nil {
		return sdktypes.NewHealthyStatus("Neo4j APOC contract not checked: GIBSON_PLATFORM_TENANT is not a tenant id: " + err.Error())
	}
	pool := c.pool()
	if pool == nil {
		return sdktypes.NewHealthyStatus("Neo4j APOC contract not checked: the data-plane pool is not up")
	}
	conn, err := pool.For(ctx, tid)
	if err != nil {
		var notProvisioned *datapool.NotProvisionedError
		if errors.As(err, &notProvisioned) {
			return sdktypes.NewHealthyStatus("Neo4j APOC contract not checked: the install tenant's data plane is not provisioned yet")
		}
		c.log.Warn("Neo4j APOC contract not checked: the install tenant's data plane is unreachable", "tenant", c.tenant, "error", err)
		return sdktypes.NewHealthyStatus("Neo4j APOC contract not checked: the install tenant's data plane is unreachable: " + err.Error())
	}
	defer conn.Release()

	err = verifyAPOCContract(ctx, c.rows(conn.Neo4j))
	switch {
	case err == nil:
		c.passed.Store(true)
		return sdktypes.NewHealthyStatus("Neo4j APOC contract verified on the install tenant's data plane")
	case errors.Is(err, errAllowlistUnreadable):
		// The procedures are installed. The allowlist needs admin to read,
		// which the tenant user does not hold; the version-links tracker in
		// zeroroot-ai/.github is the guard for that value.
		c.passed.Store(true)
		c.log.Info("Neo4j APOC procedures verified; the allowlist is not readable by the tenant user", "error", err)
		return sdktypes.NewHealthyStatus("Neo4j APOC procedures verified; the allowlist is not readable by the tenant user")
	default:
		c.log.Error("Neo4j APOC contract mismatch on the install tenant's data plane", "tenant", c.tenant, "error", err)
		return sdktypes.NewDegradedStatus("Neo4j APOC contract mismatch: "+err.Error(), map[string]any{
			"tenant":    c.tenant,
			"contract":  dataplane.ContractEnvFile,
			"allowlist": dataplane.Neo4jProcedureAllowlist,
		})
	}
}

// sessionRows adapts a pool session to the cypherRows seam.
func sessionRows(s neo4j.SessionWithContext) cypherRows {
	return func(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
		res, err := s.Run(ctx, cypher, params)
		if err != nil {
			return nil, fmt.Errorf("run %q: %w", cypher, err)
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, fmt.Errorf("collect %q: %w", cypher, err)
		}
		out := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			out = append(out, r.AsMap())
		}
		return out, nil
	}
}
