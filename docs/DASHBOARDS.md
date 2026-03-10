# Gibson Observability Dashboards

Gibson provides a suite of custom Langfuse dashboards designed for security operations teams. These dashboards offer mission-aware LLM observability with integrated knowledge graph visualizations, cost tracking, and historical analytics.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Observability Dashboard Stack                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Gibson Missions ──► Langfuse Tracing ──► Custom Dashboards             │
│         │                                        │                       │
│         │                                        ├── Active Fleet        │
│         │                                        ├── Mission Detail      │
│         │                                        └── Historical Analysis │
│         │                                                                │
│         └──► Neo4j GraphRAG ──► Browser Links ─┘                        │
│                                                                          │
│   ┌──────────────┐  ┌─────────────┐  ┌────────────────┐                │
│   │   Langfuse   │  │    Neo4j    │  │   Dashboard    │                │
│   │      UI      │──│   Browser   │  │  Configuration │                │
│   │ (port 3000)  │  │ (port 7474) │  │   (GitOps)     │                │
│   └──────────────┘  └─────────────┘  └────────────────┘                │
└─────────────────────────────────────────────────────────────────────────┘
```

## Dashboard Suite

### 1. Active Fleet Dashboard

**Purpose**: Real-time monitoring of currently running missions

**Key Metrics:**
- Running missions count
- Completed missions (last hour)
- Failed missions (last hour)
- Cost per hour
- Token consumption per hour

**Widgets:**
- **Active Missions Table** - Mission name, status, agents deployed, tokens consumed, cost, duration
- **Token Usage by Model** - Bar chart showing which LLMs are being used
- **Findings by Severity** - Bar chart of security findings (critical, high, medium, low)
- **Recent Orchestrator Decisions** - Last 10 decisions with reasoning

**Use Cases:**
- Monitor active security operations in real-time
- Track resource consumption across fleet
- Quickly identify failed or stalled missions
- Review recent orchestrator decision-making

**Auto-Refresh**: 5 seconds

### 2. Mission Detail Dashboard

**Purpose**: Deep-dive analysis of a single mission's execution

**Parameters:**
- `mission_id` - Mission identifier for filtering

**Sections:**

#### Mission Summary
- Status, duration, progress percentage
- Total tokens consumed and cost
- Findings discovered
- Graph statistics (entities, relationships)

#### Orchestrator Decisions Timeline
- Full decision history with timestamps
- Each decision shows: action, target agent, reasoning, confidence score
- Expandable full prompts and responses
- Graph state snapshot at decision time

#### Agent Execution Details
- Per-agent breakdown: duration, tool calls, findings, token usage
- Tool execution timeline with input/output
- LLM calls within agent execution
- Error details for failed agents

#### Knowledge Graph Integration
- **Neo4j Browser Links** - One-click access to mission graph
- Pre-populated Cypher queries for:
  - Full mission graph
  - Host and service discovery
  - Vulnerability relationships
  - Attack path analysis

#### Findings
- Severity, title, affected target
- Evidence and detection method
- Timestamp and discovering agent

**Use Cases:**
- Debug failed or unexpected mission behavior
- Analyze orchestrator decision-making process
- Attribute costs to specific agents or decisions
- Audit mission execution for compliance
- Visualize discovered entities and relationships

### 3. Historical Analysis Dashboard

**Purpose**: Aggregate analytics and trend analysis across all missions

**Filters:**
- Date range (default: last 7 days)
- Mission status (all, completed, failed)
- Agent types (multi-select)
- Minimum cost threshold

**Aggregate Statistics:**
- Total missions executed
- Total tokens consumed
- Total cost (USD)
- Total findings discovered
- Average mission duration

**Charts and Trends:**
- **Mission History Table** - Paginated list with all mission metadata
- **Cost Over Time** - Daily cost trend line chart
- **Token Distribution by Model** - Pie chart showing Claude vs other models
- **Findings Trend** - Stacked line chart by severity over time
- **Agent Performance** - Bar chart of average duration per agent type
- **Graph Growth** - Cumulative entities discovered over time

**Use Cases:**
- Track LLM costs over time and by team
- Identify most expensive agents or missions
- Analyze finding production rates
- Compare agent performance and efficiency
- Monitor knowledge graph growth

## Configuration

### Gibson Configuration

Add the observability section to your Gibson config (`~/.gibson/config.yaml` or deployment config):

```yaml
observability:
  # Neo4j Browser base URL for graph visualization links
  neo4j_browser_url: "http://localhost:7474"

  # Langfuse dashboard URL for UI access
  langfuse_dashboard_url: "http://localhost:3000"
```

**Environment Variable Overrides:**
```bash
export GIBSON_OBSERVABILITY_NEO4J_BROWSER_URL="https://neo4j.example.com"
export GIBSON_OBSERVABILITY_LANGFUSE_DASHBOARD_URL="https://langfuse.example.com"
```

### Langfuse Configuration

Langfuse must be enabled in Gibson config for dashboards to receive data:

```yaml
langfuse:
  enabled: true
  host: "https://cloud.langfuse.com"    # Or self-hosted URL
  public_key: "${LANGFUSE_PUBLIC_KEY}"
  secret_key: "${LANGFUSE_SECRET_KEY}"
```

See [LOGGING.md](LOGGING.md#langfuse-llm-observability) for complete Langfuse configuration details.

## Deployment

### Local Development

**Prerequisites:**
- Docker and Docker Compose
- Gibson configured and running

**Quick Start:**
```bash
# Clone the Langfuse infrastructure repo
git clone https://github.com/zero-day-ai/langfuse.git
cd langfuse

# Copy environment template and configure
cp .env.example .env
# Edit .env with your values (API keys, passwords)

# Start Langfuse and PostgreSQL
make up

# Import dashboards
make import

# Access Langfuse UI
open http://localhost:3000
```

The `zero-day-ai/langfuse` repository contains:
- Docker Compose configurations for local development
- Dashboard definitions as JSON (GitOps-friendly)
- Export/import scripts for dashboard management
- CI/CD workflows for automatic deployment

**Repository**: [https://github.com/zero-day-ai/langfuse](https://github.com/zero-day-ai/langfuse)

### Kubernetes Deployment

**Prerequisites:**
- Kubernetes cluster with kubectl access
- Helm 3.x installed
- Access to `zero-day-ai/deploy` repository

**Deployment:**
```bash
# Clone the deployment repo
git clone https://github.com/zero-day-ai/deploy.git
cd deploy

# Review and customize Langfuse values
vim helm/gibson/values.yaml

# Deploy Langfuse with Gibson
helm upgrade --install gibson ./helm/gibson \
  --namespace gibson-system \
  --create-namespace \
  --set langfuse.enabled=true \
  --set langfuse.ingress.host=langfuse.example.com \
  --set langfuse.neo4j.browserURL=https://neo4j.example.com
```

**Key Configuration:**
- `langfuse.enabled` - Enable Langfuse deployment
- `langfuse.ingress.host` - External hostname for Langfuse UI
- `langfuse.neo4j.browserURL` - Neo4j Browser URL for deep linking
- `langfuse.persistence.enabled` - PostgreSQL persistence (recommended: true)

**Kubernetes Manifests Location:**
- `helm/gibson/templates/observability/langfuse/` - Langfuse deployment
- `helm/gibson/templates/observability/neo4j/` - Neo4j deployment (if enabled)

**Repository**: [https://github.com/zero-day-ai/deploy](https://github.com/zero-day-ai/deploy)

## Neo4j Integration

### How Neo4j Links Work

Gibson automatically generates Neo4j Browser URLs with pre-populated Cypher queries for mission context. These links appear in:
- Graph write spans (`gibson.graph.store`)
- Mission summary spans
- Agent completion spans (if they wrote to graph)

**Link Format:**
```
http://localhost:7474/browser/?cmd=play&arg={encoded-cypher-query}
```

**Example Queries:**

**Full Mission Graph:**
```cypher
MATCH (n)-[r]-(m)
WHERE n.mission_id = 'mission-abc123' OR m.mission_id = 'mission-abc123'
RETURN n, r, m
```

**Hosts with Ports:**
```cypher
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE h.mission_id = 'mission-abc123'
RETURN h, p
```

**Vulnerabilities:**
```cypher
MATCH (v:Vulnerability)-[:AFFECTS]->(s:Service)
WHERE v.mission_id = 'mission-abc123'
RETURN v, s
```

### Neo4j Browser Setup

**Local Development:**
```bash
docker run -d --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:5-community
```

**Configuration:**
```yaml
graphrag:
  enabled: true
  neo4j:
    uri: "bolt://localhost:7687"
    username: "neo4j"
    password: "${NEO4J_PASSWORD}"

observability:
  neo4j_browser_url: "http://localhost:7474"
```

**Kubernetes:**
Neo4j should be deployed with:
- Ingress for browser access
- TLS/SSL for production
- Persistent volumes for data
- Proper authentication

See `zero-day-ai/deploy` for Helm chart configuration.

## Dashboard Maintenance

### Updating Dashboards

Dashboards are version-controlled as JSON in the `zero-day-ai/langfuse` repository.

**Workflow:**
1. Make changes in Langfuse UI
2. Export updated dashboard: `./scripts/export-dashboards.sh`
3. Commit changes: `git commit -m "Update Active Fleet dashboard"`
4. Push to main: `git push origin main`
5. CI/CD automatically deploys to production Langfuse

**Export Script:**
```bash
cd langfuse
export LANGFUSE_HOST="https://cloud.langfuse.com"
export LANGFUSE_API_KEY="pk-lf-..."
./scripts/export-dashboards.sh
```

**Import Script:**
```bash
cd langfuse
export LANGFUSE_HOST="https://langfuse.example.com"
export LANGFUSE_API_KEY="pk-lf-..."
./scripts/import-dashboards.sh
```

### Adding New Dashboards

1. Create dashboard in Langfuse UI
2. Export using script
3. Review JSON in `dashboards/` directory
4. Commit and push
5. CI/CD deploys automatically

## Troubleshooting

### Dashboard Shows No Data

**Check:**
1. Langfuse integration is enabled in Gibson config
2. Gibson is sending traces to Langfuse (check logs for "langfuse" entries)
3. Langfuse host URL is correct
4. API keys are valid and not expired

**Debug:**
```bash
# Check Gibson logs for Langfuse exports
gibson logs | grep langfuse

# Verify Langfuse receives traces
curl -u "${LANGFUSE_PUBLIC_KEY}:${LANGFUSE_SECRET_KEY}" \
  "${LANGFUSE_HOST}/api/public/traces" | jq
```

### Neo4j Links Don't Work

**Check:**
1. `observability.neo4j_browser_url` is correctly configured
2. Neo4j Browser is accessible from your browser (network/firewall)
3. Neo4j authentication is configured
4. URL uses correct protocol (http/https)

**Common Issues:**
- **Different network**: Neo4j is on internal network but browser is external
- **Port not exposed**: Neo4j port 7474 not accessible
- **Protocol mismatch**: Using http when Neo4j requires https

**Fix:**
For Kubernetes deployments, ensure Neo4j has an ingress:
```yaml
observability:
  neo4j_browser_url: "https://neo4j.example.com"  # Use ingress URL
```

### Dashboards Not Updating After Import

**Check:**
1. Import script completed without errors
2. Langfuse API key has write permissions
3. Dashboard IDs match between export and import
4. Browser cache cleared (hard refresh)

**Force Reimport:**
```bash
cd langfuse
./scripts/import-dashboards.sh --force
```

### High Langfuse Load Time

**Causes:**
- Large number of traces (>10,000)
- Complex dashboard queries
- Insufficient PostgreSQL resources

**Optimizations:**
1. **Add database indexes** on frequently queried fields
2. **Adjust dashboard time ranges** (shorter = faster)
3. **Increase PostgreSQL resources** (CPU, memory)
4. **Enable query caching** in Langfuse config
5. **Archive old traces** periodically

**PostgreSQL Tuning:**
```yaml
# In docker-compose.yaml or Kubernetes values
postgres:
  resources:
    limits:
      cpu: 2
      memory: 4Gi
  config:
    shared_buffers: "1GB"
    effective_cache_size: "3GB"
    work_mem: "32MB"
```

### Cost Tracking Inaccurate

**Check:**
1. LLM provider costs are up-to-date in Gibson
2. All LLM calls are instrumented
3. Token counts match actual usage

**Verify:**
```bash
# Compare Gibson cost tracking to provider billing
gibson missions list --format=json | jq '[.[] | .cost] | add'
```

If costs don't match provider billing:
1. Update cost-per-token rates in Gibson
2. Ensure all LLM calls emit cost attributes
3. Check for missed instrumentation points

## Best Practices

### Mission Naming

Use consistent mission naming for better dashboard filtering:
- Include team/project prefix: `security-ops/network-scan`
- Add timestamp for batch missions: `recon-2024-01-15`
- Use descriptive names: `vuln-scan-prod-web` not `scan-123`

### Dashboard Access Control

**Production:**
- Use Langfuse's built-in RBAC
- Restrict write access to dashboard definitions
- Separate read-only viewers from operators
- Use SSO for authentication

**Teams:**
- Create dashboard views per team
- Filter by mission name prefix
- Set up alerts for high-cost missions
- Share dashboard URLs with deep links

### Cost Management

**Monitor:**
- Set cost thresholds in dashboards
- Alert on missions exceeding budget
- Review Historical dashboard weekly
- Optimize expensive agents

**Control:**
- Use cheaper models for simple tasks
- Cache LLM responses where possible
- Limit agent retries
- Set mission timeouts

### Knowledge Graph Hygiene

**Best Practices:**
- Regular graph cleanup (archive old missions)
- Index frequently queried properties
- Deduplicate entities across missions
- Document custom node/relationship types

**Performance:**
```cypher
// Add indexes for common queries
CREATE INDEX mission_id_idx FOR (n:Entity) ON (n.mission_id);
CREATE INDEX host_ip_idx FOR (n:Host) ON (n.ip_address);
CREATE INDEX vuln_severity_idx FOR (n:Vulnerability) ON (n.severity);
```

## Related Documentation

- [LOGGING.md](LOGGING.md) - Complete observability configuration
- [MISSIONS.md](MISSIONS.md) - Mission execution and orchestration
- [MEMORY.md](MEMORY.md) - Mission memory and context management
- [zero-day-ai/langfuse](https://github.com/zero-day-ai/langfuse) - Dashboard definitions and deployment
- [zero-day-ai/deploy](https://github.com/zero-day-ai/deploy) - Kubernetes manifests and Helm charts

## Support

For issues or questions:
- GitHub Issues: [zero-day-ai/gibson/issues](https://github.com/zero-day-ai/gibson/issues)
- Langfuse Repo: [zero-day-ai/langfuse](https://github.com/zero-day-ai/langfuse)
- Deploy Repo: [zero-day-ai/deploy](https://github.com/zero-day-ai/deploy)
