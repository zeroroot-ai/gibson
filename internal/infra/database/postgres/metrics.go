package postgres

import "github.com/zeroroot-ai/gibson/internal/infra/datapool/metrics"

// recordXTenantDecryptAttempt increments gibson_xtenant_decrypt_attempt_total
// for the given tenant string. The metric definition now lives in
// internal/infra/datapool/metrics (Phase K consolidation). This wrapper keeps the
// call site in credential_dao_postgres.go unchanged.
func recordXTenantDecryptAttempt(tenant string) {
	metrics.IncXTenantDecryptAttempt(tenant)
}
