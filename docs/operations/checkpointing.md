# Gibson Checkpoint Operations Guide

## Overview

Gibson's checkpointing system provides mission pause/resume capability, enabling reliable long-running autonomous operations. Checkpoints capture complete execution state at clean boundaries, allowing missions to:

- **Pause and Resume**: Stop missions for review and continue later from exact state
- **Crash Recovery**: Automatically recover from pod restarts, node failures, or crashes
- **Human-in-the-Loop**: Request approvals before risky actions and resume based on decisions
- **Time-Travel Debugging**: Restore past states to replay or analyze execution paths
- **Thread Branching**: Explore alternative execution paths from saved states

### Key Capabilities

- **Automatic Checkpointing**: Periodic state capture during execution
- **Integrity Verification**: SHA256 checksums detect corruption
- **Compression**: Zstandard compression reduces storage costs by 60-80%
- **Encryption**: AES-256-GCM protects sensitive data at rest
- **Blob Storage**: Large objects stored separately from checkpoint metadata
- **Retention Policies**: Automatic cleanup of old checkpoints

### Use Cases

1. **Long-Running Missions**: Checkpoint every hour, resume after infrastructure maintenance
2. **Approval Workflows**: Pause before exploit execution, wait for human approval
3. **Resource Constraints**: Pause missions to free resources, resume when available
4. **Debugging**: Restore checkpoint from before error occurred, add debug logging
5. **Compliance**: Audit trail of mission state at key decision points

---

## Configuration

### Basic Configuration (gibson.yaml)

Checkpointing configuration is integrated into the main Gibson configuration file:

```yaml
# Core Redis configuration (required for checkpoints)
redis:
  url: "redis://redis:6379"
  password: "${REDIS_PASSWORD}"
  database: 0
  pool_size: 10
  connect_timeout: 5s
  read_timeout: 3s
  write_timeout: 3s

# Graceful shutdown with checkpointing
shutdown:
  timeout: 30s                    # Total shutdown timeout
  checkpoint_timeout: 5s          # Per-mission checkpoint timeout
  drain_timeout: 10s              # Request drain timeout
  agent_timeout: 15s              # Agent disconnect timeout
```

### Configuration Options Reference

Checkpointing uses Gibson's core configuration sections:

| Section | Option | Type | Default | Description |
|---------|--------|------|---------|-------------|
| `redis` | `url` | string | `redis://localhost:6379` | Redis connection URL for checkpoint storage |
| `redis` | `password` | string | `""` | Redis password (use environment variable) |
| `redis` | `database` | int | `0` | Redis database number (0-15) |
| `redis` | `pool_size` | int | `10` | Connection pool size |
| `redis` | `cluster_mode` | bool | `false` | Enable Redis Cluster mode |
| `redis` | `cluster_addrs` | []string | `[]` | Cluster node addresses |
| `redis` | `sentinel_master` | string | `""` | Sentinel master name |
| `redis` | `sentinel_addrs` | []string | `[]` | Sentinel addresses |
| `redis` | `tls_enabled` | bool | `false` | Enable TLS for Redis connections |
| `shutdown` | `checkpoint_timeout` | duration | `5s` | Timeout for checkpoint creation on shutdown |

### Encryption Configuration

Checkpoints can be encrypted at rest using various key providers. Configure encryption in the `security` section:

#### Kubernetes Secrets (Recommended for K8s)

```yaml
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  key_provider:
    type: kubernetes
    kubernetes:
      secret_name: gibson-master-key
      secret_namespace: ""           # Empty = use pod's namespace
      secret_key: master-key
```

Create the Kubernetes Secret:

```bash
# Generate a 32-byte encryption key
openssl rand -base64 32 > master-key.txt

# Create Kubernetes Secret
kubectl create secret generic gibson-master-key \
  --from-file=master-key=master-key.txt \
  --namespace gibson

# Verify the secret
kubectl get secret gibson-master-key -n gibson -o yaml
```

#### HashiCorp Vault

```yaml
security:
  key_provider:
    type: vault
    vault:
      address: https://vault.example.com:8200
      mount_path: secret
      secret_path: gibson/master-key
      key_field: key
      role: gibson
```

#### AWS Secrets Manager

```yaml
security:
  key_provider:
    type: aws
    aws:
      region: us-east-1
      secret_arn: arn:aws:secretsmanager:us-east-1:123456789:secret:gibson-master-key
```

#### Azure Key Vault

```yaml
security:
  key_provider:
    type: azure
    azure:
      vault_url: https://gibson-vault.vault.azure.net/
      secret_name: master-key
```

#### GCP Secret Manager

```yaml
security:
  key_provider:
    type: gcp
    gcp:
      project_id: my-project
      secret_name: gibson-master-key
      version: latest
```

### Retention Policies

Checkpointing implements automatic cleanup based on configurable retention policies. The system currently supports time-based retention through TTL configuration:

#### Time-Based Retention (TTL)

Configure default TTL in the checkpointer:

```go
config := checkpoint.CheckpointerConfig{
    DefaultTTL: 30 * 24 * time.Hour, // 30 days
}
```

Apply retention policy programmatically:

```go
// Delete checkpoints older than configured TTL
err := checkpointer.ApplyRetentionPolicy(ctx, threadID)
```

#### Retention Policy Types (Conceptual)

While not explicitly configured in YAML, the system supports these retention strategies:

| Policy | Description | Use Case | Storage Impact |
|--------|-------------|----------|----------------|
| `final_only` | Keep only the last checkpoint | Short missions, minimal history | ~1 checkpoint/mission |
| `all` | Keep all checkpoints | Debugging, audit trails | ~N checkpoints/mission |
| `error_only` | Keep checkpoints before errors | Error analysis | Varies by errors |
| `hourly` | Keep hourly snapshots | Long missions, time-travel | ~24*days checkpoints |
| `labeled` | Keep labeled milestones | Pre/post exploit, decisions | ~5-10/mission |

**Storage Cost Considerations**:

- Average checkpoint size: 100KB-10MB (depends on memory state)
- Compressed size: ~30-40% of original
- Storage cost: ~$0.023/GB/month (AWS S3 Standard)
- Typical mission: 5-20 checkpoints over 1-4 hours
- Estimated cost: $0.01-$0.50/mission/month

---

## CLI Commands

Gibson provides CLI commands for checkpoint management. Note that these commands are conceptual based on the implementation - the actual CLI may need to be implemented.

### Listing Checkpoints

List all checkpoints for a mission:

```bash
# List all threads for a mission
gibson checkpoint threads --mission-id <mission-id>

# Example output:
# THREAD ID                  CREATED AT           CHECKPOINTS  LAST CHECKPOINT
# 01HQXYZ...                2024-03-15 10:30:00  12          01HQXYZ...
# 01HQXAB...                2024-03-15 14:20:00  5           01HQXCD...
```

List checkpoints for a specific thread:

```bash
# List all checkpoints in a thread
gibson checkpoint list --thread-id <thread-id>

# List with limit
gibson checkpoint list --thread-id <thread-id> --limit 10

# Example output:
# CHECKPOINT ID              CREATED AT           SIZE      LABEL            ENCRYPTED
# 01HQXYZ123                2024-03-15 15:45:12  2.3 MB    pre_exploit      Yes
# 01HQXYZ122                2024-03-15 15:40:08  1.8 MB    -                Yes
# 01HQXYZ121                2024-03-15 15:35:05  1.9 MB    post_recon       Yes
```

### Inspecting Checkpoints

View detailed checkpoint information:

```bash
gibson checkpoint inspect <checkpoint-id>

# Example output:
# Checkpoint ID: 01HQXYZ123
# Thread ID: 01HQXYZ...
# Mission ID: 01HQXABC...
# Created At: 2024-03-15T15:45:12Z
# Size: 2.3 MB
# Compressed: Yes (zstd)
# Encrypted: Yes (AES-256-GCM)
# Checksum: a3f5b8c...
# Label: pre_exploit
#
# Node States:
#   recon: completed (45.2s)
#   enumerate: completed (23.1s)
#   exploit_prep: in_progress
#
# Pending Nodes:
#   exploit_execute
#   post_exploit
#   cleanup
#
# Memory:
#   Working Memory: 124 KB
#   Mission Memory: 456 KB
#
# Findings: 3
# Conversation History: 12 KB
```

### Restoring from Checkpoint

Resume a mission from a specific checkpoint:

```bash
# Restore from specific checkpoint
gibson checkpoint restore <checkpoint-id>

# Restore latest checkpoint for a thread
gibson checkpoint restore --thread-id <thread-id> --latest

# Example output:
# Restoring checkpoint 01HQXYZ123...
# Loading checkpoint data (2.3 MB)...
# Verifying integrity (checksum: a3f5b8c)...
# Decrypting with key: gibson-master-key...
# Decompressing (zstd)...
# Restoring execution state...
#
# Mission restored successfully!
# Mission ID: 01HQXABC...
# Thread ID: 01HQXYZ...
# Current Node: exploit_prep
# Pending Nodes: 3
#
# Resume with: gibson mission resume 01HQXABC...
```

### Managing Threads

Operations on thread-level checkpoint management:

```bash
# List all threads for a mission
gibson checkpoint threads --mission-id <mission-id>

# Create a new thread (branch from existing checkpoint)
gibson checkpoint thread create --checkpoint-id <checkpoint-id> --label "alternative_path"

# Delete a thread and all its checkpoints
gibson checkpoint thread delete <thread-id> --confirm

# Apply retention policy to clean up old checkpoints
gibson checkpoint thread cleanup <thread-id> --dry-run
gibson checkpoint thread cleanup <thread-id> --apply
```

### Deleting Checkpoints

Remove checkpoints to free storage:

```bash
# Delete a specific checkpoint
gibson checkpoint delete <checkpoint-id> --confirm

# Delete all checkpoints for a thread
gibson checkpoint delete --thread-id <thread-id> --all --confirm

# Delete checkpoints older than 30 days
gibson checkpoint delete --mission-id <mission-id> --older-than 30d --confirm

# Dry-run to see what would be deleted
gibson checkpoint delete --thread-id <thread-id> --all --dry-run

# Example output:
# Would delete 8 checkpoints:
#   01HQXYZ123 (2.3 MB) - pre_exploit
#   01HQXYZ122 (1.8 MB)
#   ...
# Total storage to reclaim: 15.6 MB
#
# Run with --confirm to delete
```

---

## Operational Procedures

### Pause/Resume Workflow

Step-by-step guide for pausing and resuming missions:

#### Pausing a Mission

1. **Trigger Checkpoint Creation**:
   ```bash
   # Send SIGTERM to daemon (graceful shutdown)
   kubectl scale deployment gibson-daemon --replicas=0

   # Or use API to pause specific mission
   gibson mission pause <mission-id>
   ```

2. **Verify Checkpoint Created**:
   ```bash
   # Check shutdown logs
   kubectl logs deployment/gibson-daemon --tail=50 | grep checkpoint

   # Verify checkpoint exists
   gibson checkpoint list --mission-id <mission-id>
   ```

3. **Checkpoint Creation Indicators**:
   - Log entry: `"checkpoint created" mission_id=... checkpoint_id=...`
   - Metrics: `gibson_checkpoint_created_total{outcome="success"}`
   - Redis key exists: `checkpoint:<checkpoint-id>`

#### Resuming a Mission

1. **Identify Checkpoint to Restore**:
   ```bash
   # List available checkpoints
   gibson checkpoint list --mission-id <mission-id>

   # Inspect latest checkpoint
   gibson checkpoint inspect <checkpoint-id>
   ```

2. **Restore Mission State**:
   ```bash
   # Restore from checkpoint
   gibson checkpoint restore <checkpoint-id>

   # Resume execution
   gibson mission resume <mission-id>
   ```

3. **Verify Successful Resume**:
   - Check mission status: `gibson mission status <mission-id>`
   - Monitor logs: `kubectl logs -f deployment/gibson-daemon`
   - Watch metrics: `gibson_checkpoint_restored_total{outcome="success"}`

#### Common Resume Scenarios

**Scenario 1: Overnight Pause**
```bash
# End of day - pause
gibson mission pause mission-123

# Next morning - resume
gibson mission resume mission-123  # Automatically uses latest checkpoint
```

**Scenario 2: Restore to Specific Point**
```bash
# List checkpoints with labels
gibson checkpoint list --mission-id mission-123

# Restore to pre-exploit checkpoint
gibson checkpoint restore checkpoint-pre-exploit

# Resume with caution
gibson mission resume mission-123 --step
```

**Scenario 3: Branch Execution**
```bash
# Create alternative thread from checkpoint
gibson checkpoint thread create --checkpoint-id checkpoint-123 --label "test_variant"

# Run different approach in new thread
gibson mission resume mission-123 --thread-id <new-thread-id>
```

### Crash Recovery

What to do when pods restart or crashes occur:

#### Automatic Recovery (Built-in)

Gibson daemon automatically attempts checkpoint recovery on startup:

1. **Daemon Startup Sequence**:
   ```
   [startup] Loading configuration...
   [startup] Connecting to Redis...
   [startup] Checking for active missions...
   [startup] Found mission-123 with checkpoint checkpoint-abc
   [startup] Restoring checkpoint...
   [startup] Integrity check passed
   [startup] Decrypting checkpoint...
   [startup] Mission restored, resuming execution
   ```

2. **Checkpoint Integrity Verification**:
   - SHA256 checksum validation
   - Decryption validation (if encrypted)
   - Decompression validation
   - State deserialization validation

3. **Recovery Outcomes**:
   - **Success**: Mission resumes from checkpoint state
   - **Corruption**: Logged as error, mission marked as failed
   - **Missing**: Mission starts over (if allowed by policy)

#### Manual Recovery

If automatic recovery fails:

1. **Diagnose the Issue**:
   ```bash
   # Check daemon logs
   kubectl logs deployment/gibson-daemon | grep -A 10 "checkpoint restore"

   # Check checkpoint integrity
   gibson checkpoint inspect <checkpoint-id>

   # Verify Redis connectivity
   redis-cli -h redis -a $REDIS_PASSWORD PING
   ```

2. **Common Issues and Resolutions**:

   **Checksum Mismatch**:
   ```
   Error: checkpoint integrity check failed: checksum mismatch
   ```

   Resolution:
   ```bash
   # Try previous checkpoint
   gibson checkpoint list --mission-id <mission-id>
   gibson checkpoint restore <previous-checkpoint-id>
   ```

   **Decryption Failure**:
   ```
   Error: decryption failed: key not found
   ```

   Resolution:
   ```bash
   # Verify encryption key exists
   kubectl get secret gibson-master-key -n gibson

   # Check daemon has permission to read secret
   kubectl auth can-i get secrets --as=system:serviceaccount:gibson:gibson-daemon
   ```

   **Redis Connection Failure**:
   ```
   Error: failed to load checkpoint: connection refused
   ```

   Resolution:
   ```bash
   # Check Redis health
   kubectl get pods -n gibson | grep redis

   # Test Redis connectivity
   kubectl run -it --rm redis-test --image=redis:7 --restart=Never -- \
     redis-cli -h redis.gibson.svc.cluster.local -a $REDIS_PASSWORD PING
   ```

3. **Force Restart from Beginning**:
   ```bash
   # Delete corrupted checkpoint
   gibson checkpoint delete <checkpoint-id> --force

   # Restart mission from beginning
   gibson mission restart <mission-id> --no-checkpoint
   ```

### Handling Approval Timeouts

Managing missions stuck waiting for human approvals:

#### Approval Workflow Overview

1. Mission reaches approval node
2. Checkpoint created with `ApprovalState`
3. Execution pauses, awaiting human decision
4. Timeout timer starts (default: 24 hours)
5. If timeout: mission resumes with timeout status

#### Checking Approval Status

```bash
# List pending approvals
gibson approval list --status pending

# Example output:
# APPROVAL ID    MISSION ID     NODE ID         REQUESTED AT         TIMEOUT IN   RISK
# approval-123   mission-abc    exploit_exec    2024-03-15 10:00:00  23h 45m      high
# approval-456   mission-def    data_exfil      2024-03-15 11:30:00  22h 15m      critical
```

Inspect approval details:

```bash
gibson approval inspect <approval-id>

# Example output:
# Approval Request: approval-123
# Mission: mission-abc
# Node: exploit_exec
# Requested: 2024-03-15T10:00:00Z
# Timeout: 2024-03-16T10:00:00Z (23h 45m remaining)
# Status: pending
# Risk Level: high
#
# Details:
#   Title: Execute SQL injection exploit
#   Description: Exploit vulnerable login form to extract database credentials
#   Reasoning: OWASP Top 10 vulnerability confirmed via testing
#   Impact: Read access to user database (estimated 10,000 records)
#   Estimated Duration: 5-10 minutes
#   Requires Rollback: No
#
# Proposed Actions:
#   1. Type: exploit
#      Description: Submit crafted SQL payload to login form
#      Target: https://target.example.com/login
#      Risk: high
#      Reversible: No
#      Parameters:
#        payload: "admin' OR '1'='1"
#        method: POST
#        endpoint: /api/login
#
# Current Findings: 3
#   - SQL_INJECTION_VULNERABILITY (high)
#   - WEAK_INPUT_VALIDATION (medium)
#   - ERROR_MESSAGE_DISCLOSURE (low)
```

#### Approving or Rejecting

```bash
# Approve the request
gibson approval approve <approval-id> \
  --approved-by "security-team@example.com" \
  --comments "Approved for testing in staging environment"

# Approve with modifications
gibson approval approve <approval-id> \
  --approved-by "security-team@example.com" \
  --modify-action 0 --set-param "method=GET" \
  --comments "Changed to GET request for safety"

# Reject the request
gibson approval reject <approval-id> \
  --rejected-by "security-team@example.com" \
  --comments "Too risky for production, test in staging first"

# Cancel the request
gibson approval cancel <approval-id> \
  --reason "Mission objectives changed"
```

#### Handling Timeouts

When an approval times out:

1. **Automatic Timeout Handling**:
   - Approval status changes to `timed_out`
   - Mission resumes with timeout status
   - Agent decides how to proceed (skip, retry, fail)

2. **Monitor Timeout Events**:
   ```bash
   # Check for timeout events
   kubectl logs deployment/gibson-daemon | grep "approval timeout"

   # Query Prometheus metrics
   gibson_approval_received_total{outcome="timeout"}
   ```

3. **Resolve Stuck Approvals**:
   ```bash
   # Force approval decision
   gibson approval approve <approval-id> --force

   # Or force rejection
   gibson approval reject <approval-id> --force

   # Or cancel and skip the node
   gibson approval cancel <approval-id>
   gibson mission resume <mission-id> --skip-node <node-id>
   ```

### Time-Travel Debugging

Using checkpoints to debug mission execution issues:

#### Scenario: Debugging a Failed Exploit

1. **Identify the Problem**:
   ```bash
   # Mission failed at exploit execution
   gibson mission status mission-123
   # Status: failed
   # Error: exploit_exec: connection timeout
   ```

2. **List Checkpoints Around Failure**:
   ```bash
   gibson checkpoint list --mission-id mission-123

   # CHECKPOINT ID    CREATED AT           NODE              LABEL
   # ckpt-005         15:45:12            exploit_exec      -
   # ckpt-004         15:40:08            exploit_prep      pre_exploit
   # ckpt-003         15:35:05            enumerate         post_recon
   ```

3. **Restore Pre-Failure State**:
   ```bash
   # Restore to checkpoint before exploit
   gibson checkpoint restore ckpt-004
   ```

4. **Inspect State**:
   ```bash
   # Check what the mission knew at that point
   gibson checkpoint inspect ckpt-004

   # View mission memory
   gibson mission memory get mission-123

   # View findings so far
   gibson finding list --mission-id mission-123
   ```

5. **Add Debug Logging and Retry**:
   ```bash
   # Create new thread for debugging
   gibson checkpoint thread create --checkpoint-id ckpt-004 --label "debug_exploit"

   # Enable debug logging
   gibson mission resume mission-123 --thread-id <debug-thread-id> --log-level debug

   # Watch execution
   kubectl logs -f deployment/gibson-daemon | grep mission-123
   ```

6. **Compare Execution Paths**:
   ```bash
   # Compare successful vs failed checkpoints
   gibson checkpoint diff ckpt-004 ckpt-005

   # Example output:
   # Differences:
   #   Node States:
   #     - exploit_exec: not started -> failed
   #   Memory Changes:
   #     + target_ip: 192.168.1.100
   #     + connection_attempts: 3
   #   Findings:
   #     (no changes)
   #   Error:
   #     + "connection timeout after 30s"
   ```

---

## Monitoring

### Key Metrics

Gibson exposes Prometheus metrics for checkpoint operations:

#### Counter Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `gibson_checkpoint_created_total` | `mission_id`, `thread_id`, `outcome` | Total checkpoints created (success/failure) |
| `gibson_checkpoint_restored_total` | `mission_id`, `thread_id`, `outcome` | Total checkpoints restored (success/failure) |
| `gibson_checkpoint_deleted_total` | `mission_id`, `reason` | Total checkpoints deleted |
| `gibson_approval_requested_total` | - | Total approval requests made |
| `gibson_approval_received_total` | `mission_id`, `outcome` | Approval decisions (approved/rejected/timeout) |

#### Histogram Metrics

| Metric | Labels | Buckets | Description |
|--------|--------|---------|-------------|
| `gibson_checkpoint_size_bytes` | `mission_id` | 1KB - 100MB | Checkpoint size distribution |
| `gibson_checkpoint_create_duration_seconds` | `mission_id` | 10ms - 5s | Time to create checkpoint |
| `gibson_checkpoint_restore_duration_seconds` | `mission_id` | 10ms - 5s | Time to restore checkpoint |
| `gibson_checkpoint_serialize_duration_seconds` | `format` | 10ms - 5s | Serialization time (msgpack/json) |

#### Gauge Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `gibson_active_threads_total` | `mission_id` | Current active threads per mission |
| `gibson_pending_approvals_total` | - | Current pending approval requests |

#### Example Queries

```promql
# Checkpoint creation rate (per minute)
rate(gibson_checkpoint_created_total{outcome="success"}[5m]) * 60

# Checkpoint creation failure rate
rate(gibson_checkpoint_created_total{outcome="failure"}[5m]) * 60

# Average checkpoint size
avg(gibson_checkpoint_size_bytes)

# 95th percentile checkpoint creation time
histogram_quantile(0.95, rate(gibson_checkpoint_create_duration_seconds_bucket[5m]))

# Approval timeout rate
rate(gibson_approval_received_total{outcome="timeout"}[1h])

# Pending approvals
gibson_pending_approvals_total
```

### Alerting Rules

Suggested Prometheus alert rules for checkpoint operations:

#### High Checkpoint Failure Rate

```yaml
- alert: HighCheckpointFailureRate
  expr: |
    rate(gibson_checkpoint_created_total{outcome="failure"}[5m]) > 0.1
  for: 5m
  labels:
    severity: warning
    component: checkpoint
  annotations:
    summary: "High checkpoint creation failure rate"
    description: "Checkpoint creation failing at {{ $value | humanize }} per second"
```

#### Checkpoint Restore Failures

```yaml
- alert: CheckpointRestoreFailures
  expr: |
    rate(gibson_checkpoint_restored_total{outcome="failure"}[5m]) > 0
  for: 1m
  labels:
    severity: critical
    component: checkpoint
  annotations:
    summary: "Checkpoint restore failures detected"
    description: "Mission recovery failing - {{ $value | humanize }} failures/sec"
```

#### Large Checkpoint Sizes

```yaml
- alert: LargeCheckpointSize
  expr: |
    gibson_checkpoint_size_bytes > 50000000  # 50 MB
  for: 1m
  labels:
    severity: warning
    component: checkpoint
  annotations:
    summary: "Unusually large checkpoint detected"
    description: "Checkpoint size: {{ $value | humanize }}B for mission {{ $labels.mission_id }}"
```

#### Slow Checkpoint Operations

```yaml
- alert: SlowCheckpointCreation
  expr: |
    histogram_quantile(0.95, rate(gibson_checkpoint_create_duration_seconds_bucket[5m])) > 5
  for: 5m
  labels:
    severity: warning
    component: checkpoint
  annotations:
    summary: "Checkpoint creation is slow"
    description: "95th percentile checkpoint creation time: {{ $value | humanize }}s"
```

#### Stuck Approvals

```yaml
- alert: PendingApprovalsStuck
  expr: |
    gibson_pending_approvals_total > 5
  for: 30m
  labels:
    severity: warning
    component: checkpoint
  annotations:
    summary: "Multiple pending approvals accumulating"
    description: "{{ $value }} approvals pending for >30 minutes"
```

#### Approval Timeouts

```yaml
- alert: HighApprovalTimeoutRate
  expr: |
    rate(gibson_approval_received_total{outcome="timeout"}[1h]) > 0.1
  for: 1h
  labels:
    severity: warning
    component: checkpoint
  annotations:
    summary: "High approval timeout rate"
    description: "Approvals timing out at {{ $value | humanize }} per second"
```

### Dashboard Panels

Suggested Grafana dashboard panels for checkpoint monitoring:

#### Panel 1: Checkpoint Operations Rate

```yaml
title: "Checkpoint Operations (per minute)"
type: graph
datasource: Prometheus
targets:
  - expr: rate(gibson_checkpoint_created_total{outcome="success"}[5m]) * 60
    legendFormat: "Created (Success)"
  - expr: rate(gibson_checkpoint_created_total{outcome="failure"}[5m]) * 60
    legendFormat: "Created (Failure)"
  - expr: rate(gibson_checkpoint_restored_total{outcome="success"}[5m]) * 60
    legendFormat: "Restored (Success)"
  - expr: rate(gibson_checkpoint_restored_total{outcome="failure"}[5m]) * 60
    legendFormat: "Restored (Failure)"
```

#### Panel 2: Checkpoint Size Distribution

```yaml
title: "Checkpoint Size Distribution"
type: heatmap
datasource: Prometheus
targets:
  - expr: rate(gibson_checkpoint_size_bytes_bucket[5m])
    format: heatmap
    legendFormat: "{{ le }}"
```

#### Panel 3: Checkpoint Latency

```yaml
title: "Checkpoint Operation Latency (95th percentile)"
type: graph
datasource: Prometheus
targets:
  - expr: histogram_quantile(0.95, rate(gibson_checkpoint_create_duration_seconds_bucket[5m]))
    legendFormat: "Create (p95)"
  - expr: histogram_quantile(0.95, rate(gibson_checkpoint_restore_duration_seconds_bucket[5m]))
    legendFormat: "Restore (p95)"
  - expr: histogram_quantile(0.95, rate(gibson_checkpoint_serialize_duration_seconds_bucket[5m]))
    legendFormat: "Serialize (p95)"
```

#### Panel 4: Active Threads

```yaml
title: "Active Threads per Mission"
type: graph
datasource: Prometheus
targets:
  - expr: gibson_active_threads_total
    legendFormat: "Mission {{ mission_id }}"
```

#### Panel 5: Pending Approvals

```yaml
title: "Pending Approvals"
type: stat
datasource: Prometheus
targets:
  - expr: gibson_pending_approvals_total
    instant: true
thresholds:
  - value: 0
    color: green
  - value: 5
    color: yellow
  - value: 10
    color: red
```

#### Panel 6: Approval Decisions

```yaml
title: "Approval Decisions (per hour)"
type: graph
datasource: Prometheus
targets:
  - expr: rate(gibson_approval_received_total{outcome="approved"}[5m]) * 3600
    legendFormat: "Approved"
  - expr: rate(gibson_approval_received_total{outcome="rejected"}[5m]) * 3600
    legendFormat: "Rejected"
  - expr: rate(gibson_approval_received_total{outcome="modified"}[5m]) * 3600
    legendFormat: "Modified"
  - expr: rate(gibson_approval_received_total{outcome="timeout"}[5m]) * 3600
    legendFormat: "Timeout"
```

---

## Troubleshooting

### Common Issues

#### Checkpoint Creation Fails

**Symptoms**:
- Missions cannot pause/resume
- Shutdown takes longer than expected
- Logs show checkpoint errors
- Metric: `gibson_checkpoint_created_total{outcome="failure"}` increasing

**Common Causes**:

1. **Redis Connection Issues**:
   ```
   Error: failed to save checkpoint: dial tcp: connection refused
   ```

   **Resolution**:
   ```bash
   # Check Redis health
   kubectl get pods -n gibson | grep redis
   kubectl logs -n gibson deployment/redis

   # Test connectivity
   redis-cli -h redis.gibson.svc.cluster.local -a $REDIS_PASSWORD PING

   # Check network policy
   kubectl get networkpolicies -n gibson
   ```

2. **Redis Disk Full**:
   ```
   Error: failed to save checkpoint: OOM command not allowed
   ```

   **Resolution**:
   ```bash
   # Check Redis memory usage
   redis-cli -h redis INFO memory

   # Check eviction policy
   redis-cli -h redis CONFIG GET maxmemory-policy

   # Increase Redis memory limit
   kubectl edit deployment redis -n gibson
   # Update resources.limits.memory

   # Or enable eviction
   redis-cli -h redis CONFIG SET maxmemory-policy allkeys-lru
   ```

3. **Serialization Errors**:
   ```
   Error: failed to serialize checkpoint: msgpack: unsupported type
   ```

   **Resolution**:
   - Check mission memory for unsupported types (channels, functions)
   - Ensure all state is serializable
   - Review agent harness usage

4. **Encryption Key Missing**:
   ```
   Error: encryption failed: key not found
   ```

   **Resolution**:
   ```bash
   # Verify secret exists
   kubectl get secret gibson-master-key -n gibson

   # Check secret is mounted
   kubectl describe pod gibson-daemon-xxx -n gibson | grep Mounts -A 5

   # Check RBAC permissions
   kubectl auth can-i get secrets --as=system:serviceaccount:gibson:gibson-daemon
   ```

#### Restoration Fails

**Symptoms**:
- Missions fail to resume after restart
- Checkpoints appear corrupted
- Logs show restore errors
- Metric: `gibson_checkpoint_restored_total{outcome="failure"}` increasing

**Common Causes**:

1. **Checksum Mismatch**:
   ```
   Error: checkpoint integrity check failed: checksum mismatch
   ```

   **Diagnosis**:
   ```bash
   # Inspect checkpoint
   gibson checkpoint inspect <checkpoint-id>

   # Check for data corruption
   redis-cli -h redis GET checkpoint:<checkpoint-id> | wc -c

   # Try previous checkpoint
   gibson checkpoint list --mission-id <mission-id>
   gibson checkpoint restore <previous-checkpoint-id>
   ```

   **Resolution**:
   - If persistent: check Redis persistence (RDB/AOF)
   - Verify no bit flips (hardware issue)
   - Enable Redis data checksums in redis.conf

2. **Missing Blobs**:
   ```
   Error: failed to load blob: key not found
   ```

   **Diagnosis**:
   ```bash
   # Check blob existence
   redis-cli -h redis EXISTS blob:<thread-id>:<blob-id>

   # List all blobs for thread
   redis-cli -h redis KEYS "blob:<thread-id>:*"
   ```

   **Resolution**:
   - Check Redis TTL configuration
   - Verify blob retention policy
   - Restore from Redis backup if available

3. **Encryption Key Issues**:
   ```
   Error: decryption failed: cipher: message authentication failed
   ```

   **Diagnosis**:
   ```bash
   # Verify encryption key hasn't changed
   kubectl get secret gibson-master-key -n gibson -o yaml

   # Check key rotation logs
   kubectl logs -n gibson deployment/gibson-daemon | grep "key rotation"
   ```

   **Resolution**:
   - If key rotated: restore old key temporarily
   - If key lost: checkpoints are unrecoverable
   - Always backup encryption keys!

4. **Version Mismatch**:
   ```
   Error: unsupported checkpoint version: 2 (current: 1)
   ```

   **Resolution**:
   - Checkpoint from newer Gibson version
   - Upgrade Gibson to matching version
   - Or migrate checkpoint format (if migration tool available)

#### Approval Stuck

**Symptoms**:
- Approval request not timing out
- Mission stuck in paused state
- Approval status shows pending after timeout
- Metric: `gibson_pending_approvals_total` not decreasing

**Common Causes**:

1. **Timeout Not Triggering**:
   ```
   # Approval past timeout but still pending
   gibson approval inspect <approval-id>
   Status: pending
   Timeout: 2024-03-15T10:00:00Z (5 hours ago)
   ```

   **Resolution**:
   ```bash
   # Force timeout
   gibson approval timeout <approval-id>

   # Or force approval/rejection
   gibson approval approve <approval-id> --force
   gibson approval reject <approval-id> --force
   ```

2. **Resume Failing After Approval**:
   ```
   Error: failed to resume mission after approval: checkpoint not found
   ```

   **Resolution**:
   ```bash
   # Check checkpoint still exists
   gibson checkpoint list --mission-id <mission-id>

   # Restore checkpoint manually
   gibson checkpoint restore <checkpoint-id>

   # Resume mission
   gibson mission resume <mission-id>
   ```

3. **Approval State Corruption**:
   ```bash
   # Check approval state in checkpoint
   gibson checkpoint inspect <checkpoint-id> | grep -A 20 "Approval State"
   ```

   **Resolution**:
   - Create new checkpoint without approval state
   - Resume mission without approval (if safe)
   - Or restart mission from earlier checkpoint

#### High Storage Usage

**Symptoms**:
- Redis memory growing unbounded
- Disk space filling up
- Slow checkpoint operations
- OOM errors from Redis

**Common Causes**:

1. **Too Many Checkpoints**:
   ```bash
   # Count checkpoints per mission
   redis-cli -h redis KEYS "checkpoint:*" | wc -l

   # Check storage usage
   redis-cli -h redis INFO memory | grep used_memory_human
   ```

   **Resolution**:
   ```bash
   # Apply retention policy
   gibson checkpoint cleanup --mission-id <mission-id> --older-than 7d --dry-run
   gibson checkpoint cleanup --mission-id <mission-id> --older-than 7d --apply

   # Delete completed missions
   gibson mission list --status completed | while read mission_id; do
     gibson checkpoint delete --mission-id $mission_id --all --confirm
   done
   ```

2. **Large Checkpoint Sizes**:
   ```bash
   # Find large checkpoints
   gibson checkpoint list --sort-by size --descending | head -10
   ```

   **Resolution**:
   - Review mission memory usage (trim unnecessary data)
   - Increase compression level
   - Enable blob storage threshold
   - Reduce conversation history size

3. **Blob Storage Not Enabled**:
   ```yaml
   # Configure blob storage threshold
   checkpoint:
     blob_threshold: 1048576  # 1 MB
   ```

### Debug Logging

Enable debug logging for checkpoint operations to diagnose issues:

#### Temporary Debug Logging (via Environment)

```bash
# Set environment variable for daemon
kubectl set env deployment/gibson-daemon GIBSON_LOG_LEVEL=debug -n gibson

# Watch debug logs
kubectl logs -f deployment/gibson-daemon -n gibson | grep checkpoint
```

#### Configuration-Based Debug Logging

```yaml
# gibson.yaml
logging:
  level: debug     # Set to debug for verbose checkpoint logging
  format: json     # JSON format for structured logging
```

#### Debug Log Patterns

**Checkpoint Creation**:
```
[DEBUG] checkpoint: serializing state mission_id=mission-123 thread_id=thread-456
[DEBUG] checkpoint: state size: 2.3 MB
[DEBUG] checkpoint: compressing with zstd level=3
[DEBUG] checkpoint: compressed size: 892 KB (38.7% of original)
[DEBUG] checkpoint: encrypting with key gibson-master-key
[DEBUG] checkpoint: computing checksum
[DEBUG] checkpoint: checksum=a3f5b8c...
[DEBUG] checkpoint: saving to Redis
[INFO]  checkpoint: created successfully checkpoint_id=ckpt-789 size=892KB
```

**Checkpoint Restoration**:
```
[DEBUG] checkpoint: loading from Redis checkpoint_id=ckpt-789
[DEBUG] checkpoint: loaded 892 KB
[DEBUG] checkpoint: verifying checksum expected=a3f5b8c... actual=a3f5b8c...
[DEBUG] checkpoint: checksum verified
[DEBUG] checkpoint: decrypting with key gibson-master-key
[DEBUG] checkpoint: decompressing with zstd
[DEBUG] checkpoint: decompressed to 2.3 MB
[DEBUG] checkpoint: deserializing state
[INFO]  checkpoint: restored successfully checkpoint_id=ckpt-789 mission_id=mission-123
```

**Checkpoint Errors**:
```
[ERROR] checkpoint: serialization failed mission_id=mission-123 error="msgpack: unsupported type: chan"
[ERROR] checkpoint: checksum verification failed expected=a3f5b8c... actual=f1e2d3c...
[ERROR] checkpoint: decryption failed error="cipher: message authentication failed"
[ERROR] checkpoint: Redis connection failed error="dial tcp: connection refused"
```

#### Debug Commands

```bash
# Check checkpoint exists in Redis
redis-cli -h redis GET checkpoint:<checkpoint-id> | wc -c

# Check blob references
redis-cli -h redis HGETALL checkpoint:<checkpoint-id>:metadata

# List all checkpoints
redis-cli -h redis KEYS "checkpoint:*"

# Check checkpoint TTL
redis-cli -h redis TTL checkpoint:<checkpoint-id>

# Dump checkpoint JSON (if not encrypted)
redis-cli -h redis GET checkpoint:<checkpoint-id> | base64 -d | jq .
```

### Health Checks

Verify checkpoint system health:

#### Redis Health Check

```bash
# Basic connectivity
redis-cli -h redis.gibson.svc.cluster.local -a $REDIS_PASSWORD PING
# Expected: PONG

# Check memory
redis-cli -h redis INFO memory

# Check persistence
redis-cli -h redis INFO persistence

# Check replication (if using Redis cluster)
redis-cli -h redis INFO replication
```

#### Checkpoint System Health

```bash
# Test checkpoint creation
gibson checkpoint test-create --mission-id test-mission

# Test checkpoint restoration
gibson checkpoint test-restore --checkpoint-id <test-checkpoint-id>

# Check metrics endpoint
curl http://gibson-daemon:9090/metrics | grep gibson_checkpoint
```

#### End-to-End Health Check

```bash
#!/bin/bash
# checkpoint-health-check.sh

# 1. Check Redis connectivity
if ! redis-cli -h redis PING > /dev/null 2>&1; then
  echo "ERROR: Redis not reachable"
  exit 1
fi

# 2. Check encryption key
if ! kubectl get secret gibson-master-key -n gibson > /dev/null 2>&1; then
  echo "ERROR: Encryption key not found"
  exit 1
fi

# 3. Check checkpoint metrics
metrics=$(curl -s http://gibson-daemon:9090/metrics | grep gibson_checkpoint_created_total)
if [ -z "$metrics" ]; then
  echo "ERROR: No checkpoint metrics found"
  exit 1
fi

# 4. Test checkpoint creation (dry-run)
if ! gibson checkpoint test-create --dry-run; then
  echo "ERROR: Checkpoint test creation failed"
  exit 1
fi

echo "SUCCESS: Checkpoint system healthy"
exit 0
```

---

## Best Practices

### Mission Design

Guidelines for designing missions that work well with checkpointing:

#### Where to Place Approval Nodes

1. **Before Destructive Actions**:
   ```yaml
   nodes:
     - id: enumerate_vulns
       agent: vuln_scanner

     - id: approve_exploit
       type: approval
       config:
         title: "Approve SQL Injection Exploit"
         risk_level: high
         timeout: 24h

     - id: execute_exploit
       agent: exploiter
       depends_on: [approve_exploit]
   ```

2. **At Mission Milestones**:
   ```yaml
   nodes:
     - id: initial_recon
       agent: recon

     - id: checkpoint_recon_complete
       type: checkpoint
       label: "post_recon"

     - id: vulnerability_analysis
       agent: analyzer
   ```

3. **Before Privilege Escalation**:
   ```yaml
   - id: approve_privesc
     type: approval
     config:
       title: "Approve Privilege Escalation Attempt"
       risk_level: critical
   ```

4. **Before Data Exfiltration**:
   ```yaml
   - id: approve_exfil
     type: approval
     config:
       title: "Approve Data Extraction"
       risk_level: high
   ```

#### Checkpoint Frequency Considerations

**Too Frequent** (checkpoint every 30s):
- Pros: Minimal state loss on crash
- Cons: High Redis load, storage costs, performance impact

**Too Infrequent** (checkpoint every 4h):
- Pros: Low overhead, minimal storage
- Cons: Large state loss on crash, long re-execution time

**Recommended** (checkpoint every 15-60 minutes):
- Balances recovery time vs. overhead
- Adjust based on mission criticality
- More frequent for critical missions
- Less frequent for exploratory missions

**Event-Based Checkpointing**:
```yaml
checkpoint_policy:
  automatic: true
  interval: 30m
  on_events:
    - before_approval
    - after_exploit
    - on_error
    - on_milestone
```

#### State Management Guidelines

1. **Keep Mission Memory Lean**:
   ```go
   // Good: Store only essential state
   harness.Memory().Mission().Set(ctx, "target_ip", "192.168.1.100")
   harness.Memory().Mission().Set(ctx, "exploit_status", "success")

   // Bad: Store large blobs or unnecessary data
   harness.Memory().Mission().Set(ctx, "full_nmap_output", largeXML)  // Use findings instead!
   ```

2. **Use Findings for Large Data**:
   ```go
   // Store scan results as findings, not in memory
   finding := &types.Finding{
       Title: "Port Scan Results",
       Data: scanResults,  // Large data
   }
   harness.SubmitFinding(ctx, finding)
   ```

3. **Avoid Non-Serializable State**:
   ```go
   // Bad: These cannot be checkpointed
   harness.Memory().Mission().Set(ctx, "channel", make(chan int))
   harness.Memory().Mission().Set(ctx, "function", func() {})

   // Good: Use serializable primitives
   harness.Memory().Mission().Set(ctx, "count", 42)
   harness.Memory().Mission().Set(ctx, "status", "running")
   ```

### Production Deployment

Recommendations for deploying checkpointing in production:

#### Redis Configuration for Checkpoints

**Standalone Redis**:
```yaml
# redis-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: gibson
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
        - redis-server
        - --save 60 1000                # RDB snapshot every 60s if 1000 keys changed
        - --appendonly yes              # Enable AOF
        - --appendfsync everysec        # AOF sync every second
        - --maxmemory 2gb               # Limit memory
        - --maxmemory-policy allkeys-lru  # Evict old keys when full
        resources:
          requests:
            memory: "2Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        volumeMounts:
        - name: redis-data
          mountPath: /data
      volumes:
      - name: redis-data
        persistentVolumeClaim:
          claimName: redis-pvc
```

**Redis Cluster** (for high availability):
```yaml
# gibson.yaml
redis:
  cluster_mode: true
  cluster_addrs:
    - redis-node-1.gibson.svc.cluster.local:6379
    - redis-node-2.gibson.svc.cluster.local:6379
    - redis-node-3.gibson.svc.cluster.local:6379
  password: "${REDIS_PASSWORD}"
  pool_size: 20
  max_retries: 3
```

**Redis Sentinel** (for automatic failover):
```yaml
# gibson.yaml
redis:
  sentinel_master: "gibson-master"
  sentinel_addrs:
    - sentinel-1.gibson.svc.cluster.local:26379
    - sentinel-2.gibson.svc.cluster.local:26379
    - sentinel-3.gibson.svc.cluster.local:26379
  password: "${REDIS_PASSWORD}"
  pool_size: 20
```

#### Backup Strategies

1. **Redis Persistence** (RDB + AOF):
   ```bash
   # Configure Redis for durability
   redis-cli CONFIG SET save "900 1 300 10 60 10000"
   redis-cli CONFIG SET appendonly yes
   redis-cli CONFIG SET appendfsync everysec
   ```

2. **Periodic Snapshots**:
   ```bash
   #!/bin/bash
   # checkpoint-backup.sh

   # Trigger Redis snapshot
   redis-cli BGSAVE

   # Wait for snapshot to complete
   while [ $(redis-cli LASTSAVE) -lt $(date +%s) ]; do
     sleep 1
   done

   # Copy RDB file to backup location
   cp /data/dump.rdb /backups/dump-$(date +%Y%m%d-%H%M%S).rdb
   ```

3. **Continuous Replication**:
   ```yaml
   # Use Redis replica for backup
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: redis-replica
   spec:
     template:
       spec:
         containers:
         - name: redis
           image: redis:7-alpine
           command:
           - redis-server
           - --replicaof redis-master 6379
           - --save 60 1000
           - --appendonly yes
   ```

4. **Checkpoint Export**:
   ```bash
   # Export checkpoints to external storage
   gibson checkpoint export --mission-id <mission-id> --output s3://backups/checkpoints/

   # Restore from backup
   gibson checkpoint import --input s3://backups/checkpoints/mission-123/
   ```

### Security

Security recommendations for checkpoint encryption and access control:

#### Encryption Recommendations

1. **Always Enable Encryption in Production**:
   ```yaml
   security:
     encryption_algorithm: aes-256-gcm  # Use strongest algorithm
     key_provider:
       type: kubernetes  # Or vault, aws, azure, gcp
   ```

2. **Key Rotation Policy**:
   ```bash
   # Rotate encryption keys quarterly
   # 1. Generate new key
   openssl rand -base64 32 > master-key-new.txt

   # 2. Create new secret
   kubectl create secret generic gibson-master-key-v2 \
     --from-file=master-key=master-key-new.txt \
     --namespace gibson

   # 3. Update Gibson config to use new key
   # 4. Re-encrypt existing checkpoints
   gibson checkpoint reencrypt --old-key gibson-master-key \
     --new-key gibson-master-key-v2

   # 5. Delete old key after verification
   kubectl delete secret gibson-master-key -n gibson
   ```

3. **Key Backup and Recovery**:
   ```bash
   # Backup encryption key securely
   kubectl get secret gibson-master-key -n gibson -o yaml > master-key-backup.yaml

   # Encrypt backup
   gpg --encrypt --recipient security@example.com master-key-backup.yaml

   # Store encrypted backup in secure location
   aws s3 cp master-key-backup.yaml.gpg s3://secure-backups/gibson/

   # Document key recovery procedure
   ```

#### Access Control

1. **RBAC for Checkpoint CLI**:
   ```yaml
   # checkpoint-operator-role.yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     name: checkpoint-operator
     namespace: gibson
   rules:
   - apiGroups: [""]
     resources: ["secrets"]
     resourceNames: ["gibson-master-key"]
     verbs: ["get"]
   - apiGroups: [""]
     resources: ["pods"]
     verbs: ["list", "get"]
   - apiGroups: [""]
     resources: ["pods/log"]
     verbs: ["get"]
   ```

2. **Network Policies**:
   ```yaml
   # redis-network-policy.yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: redis-access
     namespace: gibson
   spec:
     podSelector:
       matchLabels:
         app: redis
     policyTypes:
     - Ingress
     ingress:
     - from:
       - podSelector:
           matchLabels:
             app: gibson-daemon  # Only daemon can access Redis
       ports:
       - protocol: TCP
         port: 6379
   ```

3. **Audit Logging**:
   ```yaml
   # Enable audit logging for checkpoint operations
   security:
     audit_logging: true

   # Audit log entries:
   # {"event":"checkpoint.created","mission_id":"123","user":"operator@example.com","timestamp":"2024-03-15T10:00:00Z"}
   # {"event":"checkpoint.restored","checkpoint_id":"ckpt-123","user":"operator@example.com"}
   # {"event":"approval.approved","approval_id":"appr-456","approved_by":"security@example.com"}
   ```

---

## Appendix

### Redis Key Patterns

Complete list of Redis keys used by the checkpoint system:

#### Checkpoint Keys

| Key Pattern | Type | Description | TTL |
|-------------|------|-------------|-----|
| `checkpoint:<id>` | String | Checkpoint data (serialized) | Configured TTL |
| `checkpoint:<id>:metadata` | Hash | Checkpoint metadata (ID, size, checksum) | Same as checkpoint |
| `thread:<id>` | String | Thread information (mission ID, checkpoints) | No expiry |
| `thread:<id>:checkpoints` | ZSet | Checkpoint IDs ordered by timestamp | No expiry |
| `mission:<id>:threads` | ZSet | Thread IDs for mission ordered by timestamp | No expiry |
| `blob:<thread-id>:<blob-id>` | String | Large object storage (binary data) | 30 days |

#### Approval Keys

| Key Pattern | Type | Description | TTL |
|-------------|------|-------------|-----|
| `approval:<id>` | String | Approval state (JSON) | Until resolved + 7 days |
| `approval:<id>:checkpoint` | String | Associated checkpoint ID | Same as approval |
| `mission:<id>:approvals` | ZSet | Approval IDs ordered by request time | No expiry |
| `approvals:pending` | ZSet | Global pending approvals ordered by timeout | Auto-remove on resolve |

#### Index Keys

| Key Pattern | Type | Description | TTL |
|-------------|------|-------------|-----|
| `mission:<id>:checkpoint:latest` | String | Latest checkpoint ID | No expiry |
| `thread:<id>:checkpoint:latest` | String | Latest checkpoint ID for thread | No expiry |
| `checkpoints:by_size` | ZSet | Checkpoint IDs ordered by size (monitoring) | No expiry |
| `checkpoints:by_time` | ZSet | Checkpoint IDs ordered by creation time | No expiry |

#### Example Redis Commands

```bash
# List all checkpoints for a mission
redis-cli ZRANGE mission:01HQXABC...:threads 0 -1

# Get checkpoint metadata
redis-cli HGETALL checkpoint:01HQXYZ123:metadata

# List pending approvals
redis-cli ZRANGE approvals:pending 0 -1

# Get approval state
redis-cli GET approval:appr-456

# List large checkpoints
redis-cli ZREVRANGE checkpoints:by_size 0 10 WITHSCORES

# Check blob storage usage
redis-cli KEYS "blob:*" | wc -l
```

### Event Types

List of checkpoint events for monitoring and alerting:

#### Checkpoint Events

| Event Type | Level | Description | Metrics Label |
|------------|-------|-------------|---------------|
| `checkpoint.created` | INFO | Checkpoint successfully created | `outcome=success` |
| `checkpoint.create_failed` | ERROR | Checkpoint creation failed | `outcome=failure` |
| `checkpoint.restored` | INFO | Checkpoint successfully restored | `outcome=success` |
| `checkpoint.restore_failed` | ERROR | Checkpoint restoration failed | `outcome=failure` |
| `checkpoint.deleted` | INFO | Checkpoint deleted | `reason=<reason>` |
| `checkpoint.corrupted` | ERROR | Checksum verification failed | - |
| `checkpoint.expired` | WARN | Checkpoint TTL expired, deleted | `reason=expired` |

#### Thread Events

| Event Type | Level | Description |
|------------|-------|-------------|
| `thread.created` | INFO | New execution thread created |
| `thread.branched` | INFO | Thread branched from checkpoint |
| `thread.deleted` | INFO | Thread and checkpoints deleted |
| `thread.merged` | INFO | Thread merged back to main |

#### Approval Events

| Event Type | Level | Description | Metrics Label |
|------------|-------|-------------|---------------|
| `approval.requested` | INFO | Approval request created | - |
| `approval.approved` | INFO | Request approved by human | `outcome=approved` |
| `approval.rejected` | WARN | Request rejected by human | `outcome=rejected` |
| `approval.modified` | INFO | Request approved with modifications | `outcome=modified` |
| `approval.timeout` | WARN | Request exceeded timeout | `outcome=timeout` |
| `approval.cancelled` | INFO | Request cancelled | `outcome=cancelled` |

#### Recovery Events

| Event Type | Level | Description |
|------------|-------|-------------|
| `recovery.started` | INFO | Automatic recovery started |
| `recovery.checkpoint_found` | INFO | Found checkpoint for recovery |
| `recovery.restored` | INFO | Successfully restored from checkpoint |
| `recovery.failed` | ERROR | Recovery failed, mission aborted |
| `recovery.fallback` | WARN | Using fallback recovery (findings-based) |

#### Storage Events

| Event Type | Level | Description |
|------------|-------|-------------|
| `storage.cleanup` | INFO | Retention policy applied |
| `storage.warning` | WARN | Storage usage above threshold |
| `storage.critical` | ERROR | Storage full, cannot create checkpoints |
| `blob.stored` | DEBUG | Large object stored as blob |
| `blob.retrieved` | DEBUG | Blob retrieved from storage |
| `blob.deleted` | DEBUG | Blob deleted |

#### Event Structure (JSON)

```json
{
  "event": "checkpoint.created",
  "timestamp": "2024-03-15T15:45:12Z",
  "mission_id": "01HQXABC...",
  "thread_id": "01HQXYZ...",
  "checkpoint_id": "01HQXCK...",
  "size_bytes": 2345678,
  "compressed": true,
  "encrypted": true,
  "duration_ms": 234,
  "metadata": {
    "label": "pre_exploit",
    "node_id": "exploit_prep",
    "pending_nodes": 3
  }
}
```

---

## Additional Resources

- [Gibson Mission Configuration](../MISSIONS.md)
- [Redis Configuration Guide](../redis-configuration.md)
- [Kubernetes Deployment Guide](../kubernetes-deployment.md)
- [Security Best Practices](../security/best-practices.md)
- [Prometheus Metrics Reference](../observability/metrics.md)

---

**Document Version**: 1.0
**Last Updated**: 2024-03-15
**Maintained By**: Gibson Core Team
