# Gibson

**Kubernetes-Native AI Agent Framework**

Gibson is a cloud-native platform for developing, deploying, and observing autonomous AI agents. Built for Kubernetes from the ground up, it provides the infrastructure to rapidly build agents that can autonomously perform complex tasks - security testing, API discovery, network reconnaissance, compliance auditing, or any domain you can build an agent for.

## Why Gibson?

Modern AI agents need more than just an LLM. They need:

- **Orchestration** - Coordinate multiple agents in complex workflows
- **Observability** - Trace every decision, tool call, and LLM interaction
- **State Management** - Persist context across restarts and scale horizontally
- **Tool Execution** - Invoke capabilities through a distributed, type-safe architecture
- **Knowledge Persistence** - Store discoveries in a queryable graph for reasoning

Gibson provides all of this as a Kubernetes-native platform, so you can focus on building agents instead of infrastructure.

## Architecture

```
                                    ┌────────────────────────────────────────────────────────────────┐
                                    │                        Kubernetes Cluster                      │
                                    │  ┌──────────────────────────────────────────────────────────┐  │
                                    │  │                     Gibson Daemon                         │  │
                                    │  │   Orchestration · Registry · Harness · Health Probes     │  │
                                    │  │   /healthz (liveness) · /readyz (readiness)              │  │
                                    │  └────┬──────────────┬──────────────┬───────────────────────┘  │
                                    │       │              │              │                          │
                                    │       ▼              ▼              ▼                          │
                                    │  ┌─────────┐  ┌──────────────┐  ┌──────────────┐               │
                                    │  │  etcd   │  │ Redis Stack  │  │   Neo4j      │               │
                                    │  │Registry │  │State & Queue │  │  GraphRAG    │               │
                                    │  └─────────┘  └──────────────┘  └──────────────┘               │
                                    │                      │                                          │
                                    │                      ▼                                          │
                                    │  ┌──────────────────────────────────────────────────────────┐  │
                                    │  │                    Agent & Tool Pods                      │  │
                                    │  │   network-recon │ api-discovery │ nmap │ httpx │ ...     │  │
                                    │  │   HPA scaling · Resource limits · Pod disruption budgets  │  │
                                    │  └──────────────────────────────────────────────────────────┘  │
                                    └────────────────────────────────────────────────────────────────┘
                                                                   │
                                    ┌──────────────────────────────┼──────────────────────────────┐
                                    │              Observability Stack                             │
                                    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
                                    │  │ OpenTelemetry│  │  Langfuse   │  │ Prometheus/Grafana  │  │
                                    │  │   Tracing    │  │  LLM Traces │  │     Metrics         │  │
                                    │  └─────────────┘  └─────────────┘  └─────────────────────┘  │
                                    └─────────────────────────────────────────────────────────────┘
```

## Key Features

### Kubernetes-Native

- **Health Probes**: `/healthz` and `/readyz` endpoints for liveness and readiness
- **Graceful Shutdown**: SIGTERM handling with checkpoint persistence
- **Horizontal Scaling**: Stateless daemon design with Redis-backed state
- **Service Discovery**: etcd-based registry with automatic agent/tool registration
- **Resource Management**: Memory limits, CPU requests, pod disruption budgets

### Agent Development

- **Multi-LLM Support**: Anthropic Claude, OpenAI GPT, Google Gemini, Ollama (local)
- **Tool Invocation**: Type-safe Protocol Buffer APIs with distributed execution
- **Sub-agent Delegation**: Spawn and coordinate child agents
- **Three-tier Memory**: Working (ephemeral), Mission (Redis), Long-term (vector)

### Observability

- **Distributed Tracing**: OpenTelemetry integration for end-to-end visibility
- **LLM Observability**: Langfuse integration for prompt/completion tracking
- **Metrics**: Prometheus metrics for performance monitoring
- **Structured Logging**: JSON logs with trace correlation

### State Management

- **Redis Stack**: Primary state backend with RediSearch and RedisJSON
- **Checkpointing**: Mission state persistence for crash recovery
- **Event Streams**: Redis Streams for durable event processing
- **Vector Search**: Semantic search across agent memory

## Quick Start

### Prerequisites

- Kubernetes 1.28+ (or Docker for local development)
- Helm 3.x
- kubectl configured for your cluster

### Deploy to Kubernetes

```bash
# Add the Gibson Helm repository
helm repo add gibson https://charts.zero-day.ai
helm repo update

# Install Gibson with default configuration
helm install gibson gibson/gibson \
  --namespace gibson-system \
  --create-namespace \
  --set llm.anthropicApiKey=$ANTHROPIC_API_KEY

# Verify deployment
kubectl -n gibson-system get pods
kubectl -n gibson-system get svc
```

### Local Development

```bash
# Clone the repository
git clone https://github.com/zero-day-ai/gibson.git
cd gibson

# Start dependencies with Docker Compose
docker-compose up -d redis etcd neo4j

# Build and run
make build
./bin/gibson daemon start

# In another terminal
./bin/gibson daemon status
```

### Deploy Your First Agent

```bash
# Install a security agent
kubectl apply -f https://raw.githubusercontent.com/zero-day-ai/agents/main/network-recon/k8s/deployment.yaml

# Verify agent registration
gibson agent list

# Run a mission
gibson mission run recon.yaml --target my-app
```

## Core Concepts

### Components

Gibson has three types of deployable components:

| Component | Purpose | Deployment | Scaling |
|-----------|---------|------------|---------|
| **Agent** | Autonomous LLM-driven task execution | Deployment/StatefulSet | HPA on queue depth |
| **Tool** | Stateless security operations | Deployment | HPA on CPU/memory |
| **Plugin** | Stateful service integrations | StatefulSet | Manual |

### Missions

YAML-defined workflows that orchestrate agents as directed acyclic graphs:

```yaml
name: "Infrastructure Assessment"
version: "1.0.0"

nodes:
  network-scan:
    type: agent
    agent: network-recon

  service-enum:
    type: agent
    agent: service-fingerprinter
    depends_on: [network-scan]

  vuln-testing:
    type: parallel
    nodes: [web-scanner, ssh-auditor]
    depends_on: [service-enum]

constraints:
  max_duration: 2h
  checkpoint_interval: 5m
```

### Harness

The runtime environment provided to agents:

```go
func (a *MyAgent) Execute(ctx context.Context, task agent.Task, h agent.Harness) (agent.Result, error) {
    // LLM reasoning
    resp, _ := h.Complete(ctx, "primary", messages)

    // Tool execution (distributed via Redis)
    output, _ := h.CallToolProto(ctx, "nmap", &pb.NmapRequest{Target: target})

    // Sub-agent delegation
    result, _ := h.DelegateToAgent(ctx, "subdomain-enum", subtask)

    // Finding submission
    h.SubmitFinding(ctx, finding)

    // Memory persistence
    h.Memory().Mission().Set(ctx, "discovered_hosts", hosts)
}
```

## Observability

### OpenTelemetry Tracing

Gibson exports traces for every operation:

```yaml
# config.yaml
tracing:
  enabled: true
  endpoint: otel-collector.observability:4317
  service_name: gibson-daemon
  sample_rate: 1.0
```

Trace spans include:
- Mission execution lifecycle
- Agent task execution
- LLM request/response (with token counts)
- Tool invocations
- Memory operations

### Langfuse Integration

Track LLM interactions with full prompt/completion logging:

```yaml
langfuse:
  enabled: true
  host: "https://cloud.langfuse.com"
  public_key: "${LANGFUSE_PUBLIC_KEY}"
  secret_key: "${LANGFUSE_SECRET_KEY}"
```

### Prometheus Metrics

```yaml
# ServiceMonitor for Prometheus Operator
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: gibson
spec:
  selector:
    matchLabels:
      app: gibson
  endpoints:
    - port: metrics
      interval: 30s
```

Key metrics:
- `gibson_missions_total` - Mission execution counts
- `gibson_agent_executions_total` - Agent task counts
- `gibson_tool_calls_total` - Tool invocation counts
- `gibson_llm_tokens_total` - LLM token usage
- `gibson_proto_resolution_total` - Proto type resolution stats

## Kubernetes Deployment

### Helm Values

```yaml
# values.yaml
replicaCount: 3

image:
  repository: ghcr.io/zero-day-ai/gibson
  tag: latest

resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "2Gi"
    cpu: "2000m"

redis:
  url: redis://redis-master.redis:6379

etcd:
  endpoints:
    - etcd-0.etcd.etcd:2379
    - etcd-1.etcd.etcd:2379
    - etcd-2.etcd.etcd:2379

graphrag:
  enabled: true
  neo4j:
    uri: bolt://neo4j.neo4j:7687

health:
  port: 8080
  livenessPath: /healthz
  readinessPath: /readyz

llm:
  anthropicApiKey: ""  # Set via secret
  openaiApiKey: ""

observability:
  tracing:
    enabled: true
    endpoint: otel-collector.observability:4317
  langfuse:
    enabled: true
```

### Health Probes

```yaml
# Kubernetes deployment snippet
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 15

readinessProbe:
  httpGet:
    path: /readyz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Graceful Shutdown

Gibson handles SIGTERM with a multi-phase shutdown:

1. **Stop accepting new work** - Health probe returns unhealthy
2. **Checkpoint active missions** - Persist state to Redis
3. **Drain agent queues** - Wait for in-flight operations
4. **Close connections** - Clean up gRPC, Redis, etcd connections

```yaml
terminationGracePeriodSeconds: 60  # Allow time for checkpointing
```

## CLI Reference

```bash
# Daemon management
gibson daemon start      # Start the daemon
gibson daemon stop       # Graceful shutdown
gibson daemon status     # Health check
gibson daemon logs       # Tail daemon logs

# Mission operations
gibson mission run <file>           # Execute mission
gibson mission list                 # List missions
gibson mission show <id>            # Show progress
gibson mission pause <id>           # Checkpoint and pause
gibson mission resume <id>          # Resume from checkpoint

# Agent management
gibson agent list                   # List registered agents
gibson agent install <url>          # Install from URL
gibson agent logs <name>            # View agent logs

# Tool management
gibson tool list                    # List registered tools
gibson tool install <url>           # Install tool

# Findings
gibson finding list                 # List findings
gibson finding export --format json # Export findings
```

## SDK

Build agents and tools with the [Gibson SDK](https://github.com/zero-day-ai/sdk):

```go
package main

import (
    "context"
    "github.com/zero-day-ai/sdk/agent"
    "github.com/zero-day-ai/sdk/serve"
)

type MyAgent struct{}

func (a *MyAgent) Name() string        { return "my-agent" }
func (a *MyAgent) Version() string     { return "1.0.0" }
func (a *MyAgent) Description() string { return "My autonomous agent" }

func (a *MyAgent) Execute(ctx context.Context, task agent.Task, h agent.Harness) (agent.Result, error) {
    // Your agent logic here
}

func main() {
    serve.Agent(&MyAgent{},
        serve.WithHealthPort(8080),  // Kubernetes health probes
        serve.WithPort(50051),       // gRPC service port
    )
}
```

## Configuration

```yaml
# ~/.gibson/config.yaml
core:
  home_dir: ~/.gibson
  parallel_limit: 10

daemon:
  grpc_address: 0.0.0.0:50002
  health_port: 8080

redis:
  url: redis://localhost:6379
  pool_size: 10

registry:
  type: etcd
  endpoints:
    - localhost:2379

graphrag:
  enabled: true
  neo4j:
    uri: bolt://localhost:7687
    username: neo4j
    password: password

tracing:
  enabled: true
  endpoint: localhost:4317

langfuse:
  enabled: false
  host: "https://cloud.langfuse.com"
```

## Use Cases

Gibson is designed for building autonomous agents across domains:

- **Security Testing** - Network scanning, vulnerability discovery, penetration testing
- **API Discovery** - Endpoint enumeration, schema extraction, authentication testing
- **Cloud Auditing** - AWS/Azure/GCP configuration review, compliance checking
- **Infrastructure Assessment** - Asset discovery, service fingerprinting
- **Compliance Automation** - Policy enforcement, audit trail generation
- **Custom Workflows** - Any domain where autonomous agents add value

## Related Repositories

| Repository | Description |
|------------|-------------|
| [sdk](https://github.com/zero-day-ai/sdk) | Go SDK for building agents and tools |
| [tools](https://github.com/zero-day-ai/tools) | Security tool wrappers (nmap, httpx, nuclei) |
| [deploy](https://github.com/zero-day-ai/deploy) | Helm charts and Kubernetes manifests |

## License

BSL 1.1 - See LICENSE for details.

## Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.
