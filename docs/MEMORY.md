# Gibson Memory Architecture

Gibson uses a **three-tier memory system** backed by Redis, plus a separate **knowledge graph** in Neo4j. Understanding the difference is crucial:

| System | Backend | Purpose | Lifetime |
|--------|---------|---------|----------|
| **Memory** | Redis | State, coordination, agent scratch space | Mission or run scoped |
| **Knowledge Graph** | Neo4j | Discovered entities, relationships, facts | Permanent, cross-mission |

**Memory** is "what's happening now" - agent state, task context, checkpoint data.
**Knowledge Graph** is "what we've learned about the world" - hosts, ports, services, vulnerabilities, and their relationships.

## Three-Tier Memory

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Agent Memory Access                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   h.Memory().Working()    h.Memory().Mission()    h.Memory().LongTerm() │
│         │                        │                        │              │
│         ▼                        ▼                        ▼              │
│   ┌───────────┐           ┌───────────┐           ┌───────────┐         │
│   │  WORKING  │           │  MISSION  │           │ LONG-TERM │         │
│   │  MEMORY   │           │  MEMORY   │           │  MEMORY   │         │
│   ├───────────┤           ├───────────┤           ├───────────┤         │
│   │ Ephemeral │           │Persistent │           │ Semantic  │         │
│   │ In-process│           │Redis JSON │           │  Vector   │         │
│   │ LRU evict │           │   + FTS   │           │  Search   │         │
│   │ 100K token│           │ Mission   │           │ Embeddings│         │
│   │  budget   │           │  scoped   │           │           │         │
│   └───────────┘           └───────────┘           └───────────┘         │
│         │                        │                        │              │
│         └────────────────────────┼────────────────────────┘              │
│                                  ▼                                       │
│                          Redis Stack                                     │
│                   (RedisJSON + RediSearch)                              │
└─────────────────────────────────────────────────────────────────────────┘
```

### Working Memory (Ephemeral)

**Purpose**: Scratch space for the current task. Fast, in-process, automatically evicted.

**Characteristics**:
- Thread-safe in-memory storage (`sync.Map`)
- Token budget: 100,000 tokens (default)
- LRU eviction when budget exceeded
- Lost on agent restart or task completion
- Redis-backed in production for distribution

**Use Cases**:
- Intermediate computation results
- Parsed tool outputs being processed
- Temporary state during multi-step reasoning

```go
// In agent code
h.Memory().Working().Set(ctx, "parsed_hosts", hosts)
hosts, _ := h.Memory().Working().Get(ctx, "parsed_hosts")
h.Memory().Working().Delete(ctx, "parsed_hosts")
```

**Configuration**:
```yaml
memory:
  working:
    max_tokens: 100000      # Token budget
    eviction_policy: lru    # Only LRU supported
```

### Mission Memory (Persistent)

**Purpose**: Shared state across all agents within a mission. Persists across checkpoints and restarts.

**Characteristics**:
- Redis JSON documents
- Full-text search via RediSearch (BM25 scoring)
- Mission-scoped isolation (key pattern: `gibson:memory:{mission_id}:{key}`)
- Survives agent crashes and mission pauses
- Queryable with filters

**Use Cases**:
- Discovered hosts/services to share between agents
- Accumulated findings
- Cross-agent coordination state
- Data to survive checkpoints

```go
// Store data
h.Memory().Mission().Store(ctx, "discovered_hosts", hosts, map[string]any{
    "source": "network-recon",
    "scan_type": "passive",
})

// Retrieve by key
item, _ := h.Memory().Mission().Retrieve(ctx, "discovered_hosts")

// Full-text search
results, _ := h.Memory().Mission().Search(ctx, "web server nginx", 10)

// List all keys
keys, _ := h.Memory().Mission().Keys(ctx)
```

**Configuration**:
```yaml
memory:
  mission:
    cache_size: 1000        # Local cache entries
    enable_fts: true        # Full-text search
```

### Long-Term Memory (Semantic)

**Purpose**: Vector-based semantic memory for similarity search across historical data.

**Characteristics**:
- Embeddings generated via native ONNX model (all-MiniLM-L6-v2, 384 dimensions)
- Vector search with cosine similarity
- Backends: embedded (default), Redis, Qdrant, Milvus
- Cross-mission knowledge retrieval
- No external API keys required (native embedder)

**Use Cases**:
- "Have we seen similar vulnerabilities before?"
- "What attack patterns worked on similar services?"
- Finding related historical context
- Semantic deduplication

```go
// Store with embedding
h.Memory().LongTerm().Store(ctx, "finding-123",
    "SQL injection in login form via username parameter",
    map[string]any{"severity": "high", "target": "api.example.com"},
)

// Semantic search
results, _ := h.Memory().LongTerm().Search(ctx, "authentication bypass", 5, nil)

// Find similar findings
similar, _ := h.Memory().LongTerm().SimilarFindings(ctx, findingContent, 10)

// Find similar attack patterns
patterns, _ := h.Memory().LongTerm().SimilarPatterns(ctx, "brute force ssh", 5)
```

**Configuration**:
```yaml
memory:
  long_term:
    backend: embedded       # embedded, redis, qdrant, milvus
    connection_url: ""      # Required for redis/qdrant/milvus
    storage_path: ~/.gibson/vectors/{mission_id}.db
    embedder:
      provider: native      # Native ONNX embedder (no API key needed)
```

## Memory Continuity Modes

Control how mission memory is shared across multiple runs of the same mission:

| Mode | Description | Use Case |
|------|-------------|----------|
| `isolated` | Each run has completely isolated memory (default) | Independent assessments |
| `inherit` | New runs can read (not write) prior run's memory | Building on previous work |
| `shared` | All runs share the same memory namespace | Continuous monitoring |

```go
// Check continuity mode
mode := h.Memory().Mission().ContinuityMode()

// Get value from previous run (inherit/shared modes)
val, _ := h.Memory().Mission().GetPreviousRunValue(ctx, "key")

// Get history across all runs
history, _ := h.Memory().Mission().GetValueHistory(ctx, "key")
```

## Knowledge Graph (Neo4j)

The knowledge graph is **separate from memory**. It stores permanent, queryable facts about the world:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Knowledge Graph (Neo4j)                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   (Host)──[:HAS_PORT]──►(Port)──[:RUNS_SERVICE]──►(Service)             │
│     │                                                   │                │
│     ├──[:RESOLVED_TO]──►(Domain)                       │                │
│     │                                                   │                │
│     └──[:HAS_VULNERABILITY]──►(Vulnerability)◄─────────┘                │
│                                      │                                   │
│                                      └──[:DISCOVERED_BY]──►(Agent)      │
│                                                              │           │
│                                                              └──►(Mission)
│                                                                          │
│   Populated by: Tool DiscoveryResult (field 100)                        │
│   Persists: Forever (cross-mission)                                     │
│   Query: Cypher via GraphRAG                                            │
└─────────────────────────────────────────────────────────────────────────┘
```

### How It Gets Populated

Every tool returns a `DiscoveryResult` in field 100 of its response:

```protobuf
message NmapResponse {
  repeated Host hosts = 1;
  string raw_output = 2;

  // Field 100: Graph population
  gibson.graphrag.DiscoveryResult discovery = 100;
}
```

The `DiscoveryResult` contains:
- **Entities**: Hosts, ports, services, domains, vulnerabilities
- **Relationships**: Connections between entities
- **Properties**: Metadata for filtering

Gibson automatically extracts and stores these in Neo4j after each tool execution.

### Memory vs. Knowledge Graph

| Aspect | Memory (Redis) | Knowledge Graph (Neo4j) |
|--------|----------------|-------------------------|
| **What** | State, context, scratch data | Entities, relationships, facts |
| **Lifetime** | Mission/run scoped | Permanent |
| **Query** | Key lookup, FTS, vector search | Cypher graph queries |
| **Written by** | Agents directly | Tools via DiscoveryResult |
| **Use case** | "What am I working on?" | "What do we know about X?" |

**Example**:
- **Memory**: "I'm currently scanning 192.168.1.0/24, found 15 hosts so far"
- **Graph**: "Host 192.168.1.5 has port 443 running nginx 1.18, which has CVE-2021-23017"

### Querying the Graph

Agents can query the knowledge graph for reasoning:

```go
// Query hosts with specific vulnerability
results, _ := h.GraphRAG().Query(ctx, `
    MATCH (h:Host)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
    WHERE s.name = 'nginx' AND s.version < '1.19'
    RETURN h.address, p.number, s.version
`)

// Find attack paths
paths, _ := h.GraphRAG().Query(ctx, `
    MATCH path = (entry:Host)-[:CONNECTS_TO*1..3]->(target:Host)
    WHERE entry.external = true AND target.name = 'database'
    RETURN path
`)
```

## Redis Key Patterns

| Pattern | Purpose |
|---------|---------|
| `gibson:memory:{mission_id}:{key}` | Mission memory entries |
| `gibson:memory:idx:{mission_id}` | Mission memory key index |
| `gibson:working:{mission_id}:*` | Working memory (distributed) |
| `gibson:vector:{id}` | Vector store documents |
| `gibson:idx:memory` | RediSearch FTS index |
| `checkpoint:{mission_id}` | Checkpoint data (7-day TTL) |

## Configuration Reference

```yaml
# Memory configuration
memory:
  working:
    max_tokens: 100000           # Token budget before eviction
    eviction_policy: lru         # Eviction strategy

  mission:
    cache_size: 1000             # Local cache entries
    enable_fts: true             # Enable full-text search

  long_term:
    backend: embedded            # embedded, redis, qdrant, milvus
    connection_url: ""           # Connection string for external backends
    storage_path: ~/.gibson/vectors/{mission_id}.db
    embedder:
      provider: native           # Native ONNX (no API key)
      # provider: openai         # Or use OpenAI
      # model: text-embedding-3-small
      # api_key: ${OPENAI_API_KEY}

# Redis (primary state backend)
redis:
  url: "redis://localhost:6379"
  password: "${REDIS_PASSWORD}"
  database: 0
  pool_size: 10

# Neo4j (knowledge graph)
graphrag:
  enabled: true
  neo4j:
    uri: "bolt://localhost:7687"
    username: neo4j
    password: "${NEO4J_PASSWORD}"
    max_connections: 10
```

## Observability

Memory operations are traced via OpenTelemetry:

```
Span: gibson.memory.working.set
  ├── tier: working
  ├── operation: set
  └── key: discovered_hosts

Span: gibson.memory.mission.search
  ├── tier: mission
  ├── operation: search
  ├── query: "web server"
  └── results: 5

Span: gibson.memory.longterm.search
  ├── tier: longterm
  ├── operation: vector_search
  ├── query: "sql injection"
  └── top_k: 10
```

## Summary

| Tier | Backend | Scope | Persistence | Search | Use For |
|------|---------|-------|-------------|--------|---------|
| **Working** | Redis/Memory | Task | Ephemeral | Key only | Scratch space |
| **Mission** | Redis JSON | Mission | Checkpoint-safe | FTS (BM25) | Shared state |
| **Long-Term** | Vector DB | Cross-mission | Permanent | Semantic | Historical context |
| **Graph** | Neo4j | Global | Permanent | Cypher | World knowledge |
