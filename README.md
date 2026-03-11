# Gibson

**Kubernetes-Native AI Agent Framework**

Gibson is the infrastructure for building, deploying, and operating autonomous AI agents at scale. Deploy with Helm, build agents with the SDK, and let Gibson handle orchestration, state management, observability, and knowledge persistence.

## Why Gibson?

Building production AI agents requires more than an LLM wrapper. You need:

- **Orchestration** - Coordinate multiple agents in complex workflows
- **State Management** - Persist context across restarts, scale horizontally
- **Tool Execution** - Distributed, type-safe operations via Redis queues
- **Knowledge Persistence** - Store discoveries in a queryable Neo4j graph
- **Observability** - Trace every decision, tool call, and LLM interaction

Gibson provides all of this as a Kubernetes-native platform, so you can focus on building agents instead of infrastructure.

## Quick Start

### Deploy Gibson

```bash
# Add the Helm repository
helm repo add gibson https://charts.zero-day.ai
helm repo update

# Deploy to your cluster
helm install gibson gibson/gibson \
  --namespace gibson-system \
  --create-namespace \
  --set llm.anthropicApiKey=$ANTHROPIC_API_KEY

# Verify deployment
kubectl -n gibson-system get pods
```

### Build Your First Agent

Create an agent to troubleshoot Kubernetes clusters:

```go
package main

import (
    "context"
    "github.com/zero-day-ai/sdk/agent"
    "github.com/zero-day-ai/sdk/llm"
    "github.com/zero-day-ai/sdk/serve"
)

type K8sTroubleshooter struct{}

func (a *K8sTroubleshooter) Name() string        { return "k8s-troubleshooter" }
func (a *K8sTroubleshooter) Version() string     { return "1.0.0" }
func (a *K8sTroubleshooter) Description() string { return "Diagnoses Kubernetes cluster issues" }

func (a *K8sTroubleshooter) LLMSlots() []agent.SlotDefinition {
    return []agent.SlotDefinition{
        agent.NewSlotDefinition("primary", "Main reasoning LLM", true).
            WithConstraints(agent.SlotConstraints{
                MinContextWindow: 8000,
                RequiredFeatures: []string{agent.FeatureToolUse},
            }),
    }
}

func (a *K8sTroubleshooter) Execute(ctx context.Context, task agent.Task, h agent.Harness) (agent.Result, error) {
    // Use LLM to reason about the problem
    resp, _ := h.Complete(ctx, "primary", []llm.Message{
        llm.NewSystemMessage("You are a Kubernetes expert. Diagnose cluster issues."),
        llm.NewUserMessage(task.Goal),
    })

    // Execute kubectl via tool
    output, _ := h.ExecuteTool(ctx, "kubectl", &pb.KubectlRequest{
        Command: "get pods -A --field-selector=status.phase!=Running",
    })

    // Store diagnosis in memory for other agents
    h.Memory().Mission().Set(ctx, "diagnosis", resp.Content)

    return agent.NewSuccessResult(map[string]any{
        "diagnosis": resp.Content,
        "pods":      output,
    }), nil
}

func main() {
    serve.Agent(&K8sTroubleshooter{}, serve.WithPort(50051))
}
```

### Deploy the Agent

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: k8s-troubleshooter
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: agent
        image: myorg/k8s-troubleshooter:latest
        ports:
        - containerPort: 50051
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
        env:
        - name: REDIS_URL
          value: redis://gibson-redis:6379
```

### Run a Mission

```bash
# Verify agent registration
gibson agent list

# Run the agent
gibson mission run --agent k8s-troubleshooter --goal "Why are pods crashing in prod?"
```

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
│  │   k8s-troubleshooter │ log-analyzer │ kubectl │ ...      │  │
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
- **GitOps Ready**: Agents, missions, and configs are all declarative YAML

### Agent Development

Build agents in Go with the [Gibson SDK](https://github.com/zero-day-ai/sdk):

```go
func (a *MyAgent) Execute(ctx context.Context, task agent.Task, h agent.Harness) (agent.Result, error) {
    // LLM reasoning
    resp, _ := h.Complete(ctx, "primary", messages)

    // Tool execution (distributed via Redis)
    output, _ := h.ExecuteTool(ctx, "kubectl", request)

    // Sub-agent delegation
    result, _ := h.DelegateToAgent(ctx, "log-analyzer", subtask)

    // Memory persistence
    h.Memory().Mission().Set(ctx, "analysis", data)

    return agent.NewSuccessResult(output), nil
}
```

**Capabilities:**
- **Multi-LLM Support**: Anthropic Claude, OpenAI GPT, Google Gemini, Ollama (local)
- **Tool Invocation**: Type-safe Protocol Buffer APIs with distributed execution
- **Sub-agent Delegation**: Spawn and coordinate child agents
- **Three-tier Memory**: Working (ephemeral), Mission (Redis), Long-term (vector)

### Component Types

| Component | Purpose | Deployment | Scaling |
|-----------|---------|------------|---------|
| **Agent** | Autonomous LLM-driven task execution | Deployment/StatefulSet | HPA on queue depth |
| **Tool** | Stateless operations (CLI wrappers) | Deployment | HPA on CPU/memory |
| **Plugin** | Stateful service integrations | StatefulSet | Manual |

### Missions

YAML-defined workflows that orchestrate agents as directed acyclic graphs:

```yaml
name: "Cluster Health Check"
version: "1.0.0"

nodes:
  diagnose:
    type: agent
    agent: k8s-troubleshooter
    goal: "Check for unhealthy pods and resource issues"

  analyze-logs:
    type: agent
    agent: log-analyzer
    depends_on: [diagnose]
    goal: "Analyze logs for errors in problematic pods"

  report:
    type: agent
    agent: report-generator
    depends_on: [analyze-logs]
    goal: "Generate incident report"

constraints:
  max_duration: 30m
  checkpoint_interval: 5m
```

### Knowledge Graph (GraphRAG)

Every entity discovered by agents persists in Neo4j:

```
Host ──[HAS_PORT]──▶ Port ──[RUNS_SERVICE]──▶ Service ──[HAS_ENDPOINT]──▶ Endpoint
Domain ──[HAS_SUBDOMAIN]──▶ Subdomain ──[RESOLVES_TO]──▶ Host
```

- UUID-based entity identity with automatic deduplication
- CEL-based validation rules
- YAML-driven taxonomy (single source of truth)
- Cross-mission intelligence - agents learn from past runs

### Observability

Gibson uses **OpenTelemetry** as its unified observability system with GenAI semantic conventions:

- **Distributed Tracing**: Full trace propagation across daemon, agents, and tools
- **GenAI Conventions**: Token usage, cost tracking, prompt/completion logging per OTel spec
- **Prometheus Metrics**: Request rates, latencies, error rates
- **Structured Logging**: JSON logs with trace correlation

```yaml
# Helm values
observability:
  tracing:
    enabled: true
    provider: "otlp"
    endpoint: "http://otel-collector:4317"
    service_name: "gibson"
  metrics:
    enabled: true
    provider: "prometheus"
    port: 9090
  content_logging:
    enabled: true
    max_prompt_length: 10000
    max_completion_length: 10000
```

Key metrics:
- `gibson_missions_total` - Mission execution counts
- `gibson_agent_executions_total` - Agent task counts
- `gibson_tool_calls_total` - Tool invocation counts
- `gibson_llm_tokens_total` - LLM token usage

## Deployment

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

graphrag:
  enabled: true
  neo4j:
    uri: bolt://neo4j.neo4j:7687

llm:
  anthropicApiKey: ""  # Set via secret
  openaiApiKey: ""
```

### Health Probes

```yaml
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
gibson daemon start          # Start the daemon
gibson daemon stop           # Graceful shutdown
gibson daemon status         # Health check

# Mission operations
gibson mission run <file>    # Execute mission
gibson mission list          # List missions
gibson mission show <id>     # Show progress
gibson mission pause <id>    # Checkpoint and pause
gibson mission resume <id>   # Resume from checkpoint

# Agent management
gibson agent list            # List registered agents
gibson agent install <url>   # Install from URL
gibson agent logs <name>     # View agent logs

# Tool management
gibson tool list             # List registered tools
gibson tool install <url>    # Install tool
```

## Use Cases

Gibson agents can automate any domain:

| Domain | Example Agents |
|--------|----------------|
| **DevOps** | K8s troubleshooter, log analyzer, incident responder |
| **Platform Engineering** | Drift detector, cost optimizer, compliance auditor |
| **Security** | Vulnerability scanner, pentester, threat hunter |
| **Data Engineering** | Pipeline monitor, schema validator, ETL orchestrator |
| **Infrastructure** | Provisioning, configuration management, capacity planning |
| **Custom Workflows** | Any domain where autonomous agents add value |

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

observability:
  tracing:
    enabled: true
    provider: "otlp"
    endpoint: "http://localhost:4317"
    service_name: "gibson"
  metrics:
    enabled: true
    provider: "prometheus"
    port: 9090
```

## SDK

Build agents and tools with the [Gibson SDK](https://github.com/zero-day-ai/sdk):

```bash
go get github.com/zero-day-ai/sdk@latest
```

The SDK provides:
- Agent, Tool, and Plugin interfaces
- LLM abstraction with slot-based model selection
- Three-tier memory system
- GraphRAG knowledge graph helpers
- gRPC serving utilities with K8s health probes

## Local Development

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

## Related Repositories

| Repository | Description |
|------------|-------------|
| [sdk](https://github.com/zero-day-ai/sdk) | Go SDK for building agents and tools |
| [tools](https://github.com/zero-day-ai/tools) | Tool wrappers (kubectl, curl, terraform) |
| [deploy](https://github.com/zero-day-ai/deploy) | Helm charts and Kubernetes manifests |

## License

BSL 1.1 - See LICENSE for details.

## Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.
