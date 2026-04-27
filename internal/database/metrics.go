package database

import "github.com/prometheus/client_golang/prometheus"

// xTenantDecryptAttempts tracks AES-Unwrap failures that indicate a
// cross-tenant decryption attempt — i.e., the wrong tenant's KEK was used to
// decrypt a record. A non-zero value is alert-worthy (Requirement 6.5, 10.2).
//
// Phase K (runtime metrics consolidation) will move this into the datapool
// metrics package alongside the other pool counters. For now it is defined
// here so the DAO layer can increment it without importing a future package.
var xTenantDecryptAttempts = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gibson_xtenant_decrypt_attempt_total",
		Help: "Number of AES-Unwrap authentication failures indicating a cross-tenant decryption attempt. Non-zero is alert-worthy.",
	},
	[]string{"tenant"},
)

func init() {
	// Register with the default Prometheus registry. Duplicate registration
	// (e.g., in tests) is silently ignored via MustRegister's panic recovery
	// pattern — we use a safer register-and-ignore approach.
	if err := prometheus.Register(xTenantDecryptAttempts); err != nil {
		// Already registered in tests or multi-package imports; ignore.
		_ = err
	}
}

// recordXTenantDecryptAttempt increments gibson_xtenant_decrypt_attempt_total
// for the given tenant string. Call this whenever IsCrossTenantCredentialError
// returns true from a DAO Get operation.
func recordXTenantDecryptAttempt(tenant string) {
	xTenantDecryptAttempts.WithLabelValues(tenant).Inc()
}
