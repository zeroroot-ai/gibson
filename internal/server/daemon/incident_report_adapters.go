// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/incidentreport"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// registerIncidentReport registers gibson.tenant.v1.IncidentReportService
// (ADR-0180, gibson#1480). It reads the graph of the tenant through the
// graph querier of the daemon, the Timeline of the tenant through the brain registry, and
// the grants from the platform database. The tenant comes from the context of
// each call.
func (d *daemonImpl) registerIncidentReport(ctx context.Context, srv *grpc.Server) error {
	if d.brainRegistry == nil {
		return errors.New("daemon: IncidentReportService needs the brain registry")
	}
	if d.platformDB == nil {
		return errors.New("daemon: IncidentReportService needs the platform database")
	}
	reader, err := incidentreport.NewReader(
		incidentreport.QuerierGraph{Graph: d.incidentGraph},
		incidentreport.BrainHistory{Registry: d.brainRegistry},
		incidentreport.StoreGrants{
			Source:  capabilitygrant.NewCapabilityGrantStore(d.platformDB),
			Changes: auditGrantChanges{q: audit.NewQuery(d.platformDB)},
		},
	)
	if err != nil {
		return fmt.Errorf("daemon: IncidentReportService: %w", err)
	}
	tenantv1.RegisterIncidentReportServiceServer(srv, api.NewIncidentReportService(reader, d.logger.WithComponent("incident-report").Slog()))
	d.logger.Info(ctx, "IncidentReportService registered (ADR-0180)")
	return nil
}

// incidentGraph returns the graph querier of the daemon as the graph reader of
// the incident report, or nil while the daemon has not built it.
func (d *daemonImpl) incidentGraph() incidentreport.TenantGraph {
	if g, ok := any(d.graphragQuerier).(incidentreport.TenantGraph); ok {
		return g
	}
	return nil
}

// auditGrantChanges reads the audit records of the grant changes of one agent
// principal (internal/server/admin/grants_admin.go). The person who gave a grant
// is the actor of its record.
type auditGrantChanges struct{ q *audit.Query }

var _ incidentreport.GrantChangeSource = auditGrantChanges{}

// GrantChanges returns the records of agent_grant_added and agent_grant_removed
// whose target is the principal, up to the time until. The tenant is a predicate
// of the audit read, so a principal of another tenant has no record here. A read
// that holds more records than the bound is an error, because a missing old
// record would name the wrong grantor.
func (a auditGrantChanges) GrantChanges(
	ctx context.Context, tenant, principal string, until time.Time,
) ([]audit.PgEntry, error) {
	var all []audit.PgEntry
	for _, action := range []string{"agent_grant_added", "agent_grant_removed"} {
		done := false
		for page := range auditMaxPages {
			got, total, err := a.q.List(ctx, tenant,
				audit.Filters{Action: action, TargetID: principal, Until: &until}, auditPageSize, page*auditPageSize)
			if err != nil {
				return nil, fmt.Errorf("audit list of %s: %w", action, err)
			}
			all = append(all, got...)
			if (page+1)*auditPageSize >= total {
				done = true
				break
			}
		}
		if !done {
			return nil, fmt.Errorf("the principal %q has more than %d %s records",
				principal, auditMaxPages*auditPageSize, action)
		}
	}
	return all, nil
}
