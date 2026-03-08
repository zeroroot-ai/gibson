# Kubernetes Deployment Guide

This guide covers deploying the Gibson daemon to Kubernetes with proper configuration for graceful shutdown, health checks, and production readiness.

## Graceful Shutdown Configuration

Gibson implements a phased graceful shutdown process to ensure running missions are checkpointed, agents are notified, and connections are cleanly closed. Proper Kubernetes configuration is essential to allow this process to complete.

### Shutdown Phases

When the Gibson daemon receives a SIGTERM signal (from Kubernetes during pod termination), it executes the following phases:

1. **Health Unhealthy** (1s): Sets health endpoint to return 503, stopping new traffic
2. **Drain Requests** (default 10s): Waits for in-flight gRPC requests to complete
3. **Checkpoint Missions** (default 5s): Saves running mission state to Redis
4. **Notify Agents** (default 15s): Gracefully disconnects connected agents
5. **Close Connections** (5s): Closes Redis, Neo4j, and etcd connections

Total default shutdown time: **30 seconds** (configurable via `GIBSON_SHUTDOWN_TIMEOUT`)

### Required Kubernetes Settings

#### 1. Termination Grace Period

The `terminationGracePeriodSeconds` must be **greater than** the configured shutdown timeout to prevent Kubernetes from force-killing the pod before graceful shutdown completes.

**Recommended**: `terminationGracePeriodSeconds` = `GIBSON_SHUTDOWN_TIMEOUT` + 10 seconds buffer

```yaml
spec:
  template:
    spec:
      terminationGracePeriodSeconds: 40  # 30s shutdown + 10s buffer
```

#### 2. PreStop Hook

Add a `preStop` hook with a short sleep to ensure the pod is removed from endpoints before shutdown begins. This prevents new connections during the shutdown window.

```yaml
spec:
  template:
    spec:
      containers:
      - name: gibson
        lifecycle:
          preStop:
            exec:
              command: ["/bin/sh", "-c", "sleep 5"]
```

**Why this matters**: Kubernetes removes pods from Service endpoints asynchronously. The 5-second sleep ensures:
- The pod is removed from load balancer rotation
- In-flight requests have a grace period to complete
- New requests are routed to healthy pods

#### 3. Readiness Probe

Configure a readiness probe that checks Gibson's health endpoint. During shutdown, this endpoint returns 503, which tells Kubernetes to stop routing traffic.

```yaml
spec:
  template:
    spec:
      containers:
      - name: gibson
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 2
          successThreshold: 1
          failureThreshold: 2
```

**Health Endpoint Behavior**:
- **Healthy**: Returns 200 OK with `{"status": "ready"}`
- **Shutting down**: Returns 503 Service Unavailable with `{"status": "shutting_down", "reason": "graceful_shutdown"}`

#### 4. Liveness Probe

The liveness probe should have a longer timeout to avoid restarting pods during startup or legitimate slow operations.

```yaml
spec:
  template:
    spec:
      containers:
      - name: gibson
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
```

## Complete Deployment Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gibson-daemon
  namespace: gibson
  labels:
    app: gibson
    component: daemon
spec:
  replicas: 1  # Gibson daemon should run as a singleton per cluster
  strategy:
    type: Recreate  # Prevent multiple daemon instances
  selector:
    matchLabels:
      app: gibson
      component: daemon
  template:
    metadata:
      labels:
        app: gibson
        component: daemon
    spec:
      # Graceful shutdown configuration
      terminationGracePeriodSeconds: 40

      containers:
      - name: gibson
        image: gibson:latest
        imagePullPolicy: IfNotPresent

        # Environment variables for shutdown configuration
        env:
        - name: GIBSON_SHUTDOWN_TIMEOUT
          value: "30s"
        - name: GIBSON_SHUTDOWN_DRAIN_TIMEOUT
          value: "10s"
        - name: GIBSON_SHUTDOWN_CHECKPOINT_TIMEOUT
          value: "5s"
        - name: GIBSON_SHUTDOWN_AGENT_TIMEOUT
          value: "15s"
        - name: GIBSON_HEALTH_PORT
          value: "8080"
        - name: GIBSON_DAEMON_GRPC_ADDR
          value: "0.0.0.0:50002"
        - name: GIBSON_REDIS_URL
          valueFrom:
            secretKeyRef:
              name: gibson-secrets
              key: redis-url
        - name: GIBSON_NEO4J_URI
          valueFrom:
            secretKeyRef:
              name: gibson-secrets
              key: neo4j-uri

        ports:
        - name: grpc
          containerPort: 50002
          protocol: TCP
        - name: health
          containerPort: 8080
          protocol: TCP
        - name: callback
          containerPort: 50001
          protocol: TCP

        # Readiness probe - checks /ready endpoint
        readinessProbe:
          httpGet:
            path: /ready
            port: health
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 2
          successThreshold: 1
          failureThreshold: 2

        # Liveness probe - checks /healthz endpoint
        livenessProbe:
          httpGet:
            path: /healthz
            port: health
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3

        # PreStop hook - wait for endpoint removal
        lifecycle:
          preStop:
            exec:
              command: ["/bin/sh", "-c", "sleep 5"]

        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"

        volumeMounts:
        - name: gibson-data
          mountPath: /root/.gibson

      volumes:
      - name: gibson-data
        persistentVolumeClaim:
          claimName: gibson-pvc

---
apiVersion: v1
kind: Service
metadata:
  name: gibson-daemon
  namespace: gibson
spec:
  type: ClusterIP
  ports:
  - name: grpc
    port: 50002
    targetPort: grpc
    protocol: TCP
  - name: callback
    port: 50001
    targetPort: callback
    protocol: TCP
  selector:
    app: gibson
    component: daemon
```

## Shutdown Environment Variables

Configure shutdown behavior via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `GIBSON_SHUTDOWN_TIMEOUT` | `30s` | Total shutdown timeout (all phases must complete within this) |
| `GIBSON_SHUTDOWN_DRAIN_TIMEOUT` | `10s` | Time to wait for in-flight requests to complete |
| `GIBSON_SHUTDOWN_CHECKPOINT_TIMEOUT` | `5s` | Time allowed for mission checkpointing |
| `GIBSON_SHUTDOWN_AGENT_TIMEOUT` | `15s` | Time to wait for agents to disconnect |
| `GIBSON_HEALTH_PORT` | `8080` | Port for health check endpoints |

**Important**: Ensure `terminationGracePeriodSeconds` > `GIBSON_SHUTDOWN_TIMEOUT` + buffer (recommended 10s)

## Testing Graceful Shutdown

### 1. Verify Health Endpoint

```bash
# Check health endpoint is responding
kubectl exec -it <pod-name> -n gibson -- curl http://localhost:8080/ready

# Expected: {"status": "ready"}
```

### 2. Test Graceful Shutdown

```bash
# Delete pod and watch shutdown logs
kubectl delete pod <pod-name> -n gibson --wait=false
kubectl logs -f <pod-name> -n gibson

# Look for shutdown phase logs:
# - "graceful shutdown initiated"
# - "starting shutdown phase phase=health_unhealthy"
# - "starting shutdown phase phase=drain_requests"
# - "starting shutdown phase phase=checkpoint_missions"
# - "starting shutdown phase phase=notify_agents"
# - "starting shutdown phase phase=close_connections"
# - "graceful shutdown completed"
```

### 3. Verify Checkpoint Persistence

```bash
# Start a mission, then terminate the pod
# Check Redis for checkpoints:
redis-cli KEYS "gibson:checkpoint:*"

# Should show checkpoint keys for running missions
```

### 4. Monitor Shutdown Metrics

Shutdown metrics are emitted as structured JSON logs:

```json
{
  "level": "info",
  "msg": "shutdown metrics",
  "metrics_json": "{
    \"start_time\": \"2026-03-07T21:20:00Z\",
    \"total_duration_ms\": 28500,
    \"phases_duration\": {
      \"health_unhealthy\": 950000000,
      \"drain_requests\": 8200000000,
      \"checkpoint_missions\": 3100000000,
      \"notify_agents\": 12300000000,
      \"close_connections\": 3950000000
    },
    \"missions_checkpointed\": 2,
    \"agents_disconnected\": 5,
    \"requests_drained\": 0,
    \"error_count\": 0,
    \"forced_exit\": false
  }"
}
```

## Common Issues

### Pod Force Killed Before Shutdown Completes

**Symptom**: Logs show shutdown started but not completed, pod terminated abruptly

**Solution**: Increase `terminationGracePeriodSeconds`:
```yaml
terminationGracePeriodSeconds: 60  # Increase if shutdown takes longer
```

### New Requests During Shutdown

**Symptom**: Requests fail during pod termination

**Solution**: Ensure `preStop` hook has adequate sleep time and readiness probe is configured:
```yaml
lifecycle:
  preStop:
    exec:
      command: ["/bin/sh", "-c", "sleep 10"]  # Increase if needed
```

### Missions Not Checkpointed

**Symptom**: Running missions lost on restart

**Solution**:
1. Verify Redis is accessible during shutdown
2. Increase `GIBSON_SHUTDOWN_CHECKPOINT_TIMEOUT`
3. Check logs for checkpoint errors

### Health Probe Failures During Startup

**Symptom**: Pod restarted during initialization

**Solution**: Increase `initialDelaySeconds` for readiness probe:
```yaml
readinessProbe:
  initialDelaySeconds: 30  # Allow more time for startup
```

## Best Practices

1. **Always set `terminationGracePeriodSeconds`** to at least 10 seconds more than `GIBSON_SHUTDOWN_TIMEOUT`
2. **Use `preStop` hook** to ensure endpoints are updated before shutdown begins
3. **Monitor shutdown metrics** in production to tune timeout values
4. **Test graceful shutdown** in staging environment with realistic load
5. **Configure resource limits** to prevent OOM kills during shutdown
6. **Use `Recreate` strategy** for daemon deployment to prevent multiple instances
7. **Verify checkpoint recovery** after pod restarts to ensure mission continuity

## References

- [Kubernetes Pod Lifecycle](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/)
- [Kubernetes Container Hooks](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/)
- [Kubernetes Health Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
