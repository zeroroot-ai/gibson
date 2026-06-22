package metrics

// DataPlaneAlertRules contains Prometheus alerting rules for the data-plane
// metrics defined in this package. These rules are exported as Go constants so
// they can be embedded into Helm chart ConfigMaps or Kubernetes PrometheusRule
// resources via the GitOps deploy pipeline at enterprise/deploy/.
//
// Threshold rationale is documented inline. Alerts are grouped by severity:
//
//   - critical: page immediately; indicates a security invariant violation.
//   - warning: wake someone during business hours; indicates degraded performance.
//   - info: track in Grafana; no human action required but worth monitoring.
//
// Spec: database-per-tenant-data-plane, Phase K, task 11.1.
// Requirements: 6.5, 16.4.
const DataPlaneAlertRules = `
groups:
  - name: gibson_dataplane
    rules:

      # -----------------------------------------------------------------------
      # CRITICAL: Any cross-tenant decryption attempt is a security event.
      # Requirement 6.5 mandates immediate alerting when the per-tenant KEK
      # decrypts a record from a different tenant — this can only happen if
      # the connection pool returns the wrong tenant's Conn (pool bug) or if
      # an adversary has manipulated stored ciphertext. Either scenario requires
      # immediate investigation.
      #
      # Threshold: any increment above zero within a 5-minute window.
      # For: 0m — fire immediately, do not wait for persistence.
      # -----------------------------------------------------------------------
      - alert: GibsonCrossTenantDecryptAttempt
        expr: increase(gibson_xtenant_decrypt_attempt_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
          team: platform-security
        annotations:
          summary: "Cross-tenant decryption attempt detected for tenant {{ $labels.tenant }}"
          description: >
            gibson_xtenant_decrypt_attempt_total has incremented for tenant
            {{ $labels.tenant }}. This indicates the pool returned a Conn whose
            KEK does not match the stored ciphertext — a potential tenant isolation
            breach. Investigate pool_impl.go For() singleflight and evictor race
            conditions immediately. See Requirement 6.5.

      # -----------------------------------------------------------------------
      # CRITICAL: Pool initialization failures on the not_provisioned reason
      # indicate the tenant-operator has not completed provisioning. In a healthy
      # system this should only occur briefly after tenant creation. Sustained
      # failures indicate the tenant-operator is stuck or the CRD status is wrong.
      #
      # Threshold: > 10 failures in 5 minutes for the same tenant+store.
      # For: 2m — allow brief transient failures during tenant creation.
      # -----------------------------------------------------------------------
      - alert: GibsonPoolInitNotProvisioned
        expr: >
          increase(gibson_pool_init_failures_total{reason="not_provisioned"}[5m]) > 10
        for: 2m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Tenant {{ $labels.tenant }} {{ $labels.store }} pool repeatedly not provisioned"
          description: >
            Pool initialization for tenant {{ $labels.tenant }} store {{ $labels.store }}
            is repeatedly failing with reason=not_provisioned. The tenant-operator may be
            stuck or the Tenant CRD status.dataPlane field is not being updated.
            Check the tenant-operator logs and the Tenant CRD for {{ $labels.tenant }}.

      # -----------------------------------------------------------------------
      # WARNING: Pool acquire p99 latency exceeding 500ms indicates the
      # connection warm-up (Postgres pool create, Redis select, Neo4j session
      # open) is unusually slow. This does not affect already-warm tenants but
      # degrades first-request latency for cold tenants.
      #
      # Threshold: 99th percentile over 5 minutes > 0.5 seconds.
      # For: 5m — sustained, not a single spike.
      # -----------------------------------------------------------------------
      - alert: GibsonPoolAcquireHighLatency
        expr: >
          histogram_quantile(0.99,
            rate(gibson_pool_acquire_duration_seconds_bucket[5m])
          ) > 0.5
        for: 5m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "Pool acquire p99 latency {{ $value | humanizeDuration }} > 500ms (store={{ $labels.store }})"
          description: >
            gibson_pool_acquire_duration_seconds p99 is {{ $value | humanizeDuration }}
            for store={{ $labels.store }}. Cold-tenant warm-up is slower than expected.
            Check Postgres connection latency, Redis SELECT latency, and Neo4j
            session open time. If latency is due to provisioning check, inspect
            the Kubernetes API server RTT.

      # -----------------------------------------------------------------------
      # WARNING: Provisioning check CRD unavailability means the daemon cannot
      # verify tenant provisioning status. In fail-closed mode (the default),
      # this blocks all Pool.For() calls for tenants whose cache has expired.
      # A sustained spike here will surface as 503s to tenants.
      #
      # Threshold: > 5 failures per minute sustained.
      # For: 2m.
      # -----------------------------------------------------------------------
      - alert: GibsonProvisioningCheckCRDUnavailable
        expr: >
          rate(gibson_dataplane_provisioning_check_failures_total{reason="crd_unavailable"}[1m]) > 5
        for: 2m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "CRD provisioning checks failing at {{ $value | humanize }}/s"
          description: >
            gibson_dataplane_provisioning_check_failures_total{reason="crd_unavailable"}
            is spiking. The daemon cannot reach the Kubernetes API server to verify
            tenant provisioning status. Pool.For() calls for cold tenants will be
            rejected. Check kube-apiserver health and daemon RBAC permissions on the
            Tenant CRD. In-cache tenants are not affected during cacheTTL window.

      # -----------------------------------------------------------------------
      # WARNING: Excessive idle evictions suggest the IdleTTL is too short for
      # actual tenant traffic patterns, causing pool thrash (evict then re-init
      # on next request). This is not a correctness issue but degrades latency.
      #
      # Threshold: > 50 evictions per minute across all tenants.
      # For: 10m — sustained thrash, not a deployment burst.
      # -----------------------------------------------------------------------
      - alert: GibsonPoolIdleEvictionThrash
        expr: sum(rate(gibson_pool_idle_eviction_total[1m])) > 50
        for: 10m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "Pool idle eviction rate {{ $value | humanize }}/s — possible pool thrash"
          description: >
            The aggregate idle eviction rate across all tenants is
            {{ $value | humanize }} evictions/second. This suggests IdleTTL in the
            datapool.Config is shorter than the inter-request interval for many
            tenants, causing pools to be evicted and re-initialized on each request.
            Consider increasing Config.IdleTTL. Current eviction breakdown by tenant
            is in the gibson_pool_idle_eviction_total counter.

      # -----------------------------------------------------------------------
      # INFO: Admin pool acquisitions are audit events (Requirement 11.3).
      # This rule fires an info-level alert when the acquisition rate is
      # unexpectedly high, which may indicate a runaway cross-tenant analytics
      # job or a misconfigured billing aggregator.
      #
      # Threshold: > 100 acquisitions per minute from a single (rpc, subject).
      # For: 5m.
      # -----------------------------------------------------------------------
      - alert: GibsonAdminPoolHighAcquisitionRate
        expr: >
          rate(gibson_admin_pool_acquire_total[1m]) > 100
        for: 5m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "Admin pool acquisition rate {{ $value | humanize }}/s for {{ $labels.subject }} on {{ $labels.rpc }}"
          description: >
            gibson_admin_pool_acquire_total is spiking for subject={{ $labels.subject }}
            rpc={{ $labels.rpc }}. Every AdminConn acquisition is an audited cross-tenant
            access event. A sustained rate this high is unusual and may indicate a
            misconfigured or runaway operator process. Review the audit log for
            {{ $labels.subject }}.
`
