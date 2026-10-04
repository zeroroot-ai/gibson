package daemon

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// enrollmentRunLimits reads the runtime cap an AgentEnrollment declared for
// an agent (gibson#597) from the platform Postgres the tenant-operator
// reports into (DaemonOperatorService.SetAgentEnrollmentLimits). The pool
// is resolved per call because it is initialized after the harness factory
// is built (daemon Start), the same reason the credential source is lazy.
type enrollmentRunLimits struct {
	db func() *sql.DB
}

var errPlatformDBUnset = errors.New("enrollment run limits: platform Postgres not configured")

func (l *enrollmentRunLimits) AgentRunLimit(ctx context.Context, tenant, agentName string) (time.Duration, bool, error) {
	db := l.db()
	if db == nil {
		return 0, false, errPlatformDBUnset
	}
	return api.AgentRunLimit(ctx, db, tenant, agentName)
}
