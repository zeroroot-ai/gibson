# End-to-End Taxonomy Relationships Test

This document provides a complete end-to-end test procedure to validate that Gibson's discovery flow correctly creates UUID-based entities and taxonomy-driven relationships in Neo4j.

## Overview

This test verifies:
- UUID-based entity identity system
- Taxonomy-driven relationship creation (HAS_PORT, RUNS_SERVICE, etc.)
- Parent-child relationships via foreign key properties
- Mission scoping via BELONGS_TO relationships
- No orphaned nodes or broken references

## Prerequisites

Before running this test, ensure you have:

- **Docker** installed (for Neo4j)
- **Go 1.21+** installed
- **Gibson** repository cloned
- **Network-recon** agent available (local or from GitHub)
- **cypher-shell** CLI (optional, for direct queries)

## Test Procedure

### 1. Start Neo4j Test Instance

```bash
# Start Neo4j in Docker with test credentials
docker run -d \
  --name neo4j-test \
  -p 7474:7474 \
  -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/testpassword \
  neo4j:latest

# Wait for Neo4j to start (check logs)
docker logs -f neo4j-test

# Look for: "Remote interface available at http://localhost:7474/"
# Press Ctrl+C once you see this message
```

**Verify Neo4j is running:**
- Open browser to http://localhost:7474
- Login with username `neo4j` and password `testpassword`
- You should see the Neo4j Browser interface

### 2. Build Gibson

```bash
# Navigate to Gibson repository
cd /home/anthony/Code/zeroroot.ai/opensource/gibson

# Build Gibson CLI
make build

# Verify build
./bin/gibson version
```

### 3. Configure Neo4j Connection

Create a test configuration file:

```bash
cat > /tmp/gibson-test-config.yaml <<'EOF'
neo4j:
  uri: bolt://localhost:7687
  username: neo4j
  password: testpassword
  database: neo4j

llm:
  providers:
    - name: anthropic
      type: anthropic
      api_key: ${ANTHROPIC_API_KEY}

logging:
  level: info
  format: json
EOF
```

**Note:** Ensure `ANTHROPIC_API_KEY` environment variable is set:
```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

### 4. Install Network-Recon Agent

**Option A: From local development**
```bash
# If you have the agent locally
cd /home/anthony/Code/zeroroot.ai/enterprise/agents/network-recon
make build
```

**Option B: From GitHub**
```bash
gibson agent install github.com/zeroroot-ai/network-recon
```

### 5. Create Test Mission

Create a mission configuration file:

```bash
cat > /tmp/test-mission.yaml <<'EOF'
apiVersion: gibson.zeroroot.ai/v1
kind: Mission
metadata:
  name: taxonomy-relationship-test
  description: E2E test for UUID-based entities and taxonomy relationships

spec:
  # Target a safe, public test server
  target: scanme.nmap.org

  # Alternative: test against localhost
  # target: 127.0.0.1

  # Scope configuration
  scope:
    in_scope:
      - scanme.nmap.org
      # - 127.0.0.1

  # Agent configuration
  agents:
    - name: network-recon
      config:
        scan_type: quick
        port_range: "22,80,443,8080"
        max_hosts: 5

  # LLM slot assignments
  llm_assignments:
    network-recon:
      primary:
        provider: anthropic
        model: claude-3-5-sonnet-20241022
        temperature: 0.0

  # Output configuration
  output:
    neo4j:
      enabled: true
      track_relationships: true
    findings:
      enabled: true
      format: json
EOF
```

### 6. Run the Mission

```bash
# Run Gibson mission with test config
gibson mission run \
  --config /tmp/gibson-test-config.yaml \
  --mission /tmp/test-mission.yaml

# Mission should execute and complete
# Watch for log messages about Neo4j relationships
```

**Expected output includes:**
- Agent initialization messages
- Discovery results (hosts, ports, services found)
- Neo4j relationship creation messages
- Mission completion status

### 7. Verify Neo4j Relationships

Now we'll query Neo4j to verify the relationships were created correctly.

#### Option A: Using Neo4j Browser (Visual)

1. Open http://localhost:7474 in your browser
2. Login with `neo4j` / `testpassword`
3. Run the queries below in the query editor

#### Option B: Using cypher-shell (CLI)

```bash
# Install cypher-shell if not available
# On Ubuntu/Debian:
# sudo apt-get install cypher-shell

# Or use it from Docker:
alias cypher="docker exec -it neo4j-test cypher-shell -u neo4j -p testpassword"
```

#### Verification Queries

**Query 1: Check hosts exist with UUIDs**
```cypher
MATCH (h:Host)
RETURN h.id AS host_id, h.ip AS ip_address, h.hostname AS hostname
LIMIT 10;
```

**Expected:** Multiple hosts with UUID strings in `id` field

---

**Query 2: Check HAS_PORT relationships**
```cypher
MATCH (h:Host)-[r:HAS_PORT]->(p:Port)
RETURN
  h.ip AS host_ip,
  type(r) AS relationship_type,
  p.number AS port_number,
  p.host_id AS port_host_id,
  h.id AS host_id
LIMIT 10;
```

**Expected:**
- Relationship type is `HAS_PORT`
- `port_host_id` matches `host_id`

---

**Query 3: Verify port foreign keys match host IDs**
```cypher
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE h.id = p.host_id
RETURN count(*) AS correct_foreign_keys;
```

**Expected:** Count equals total number of HAS_PORT relationships (100% match)

---

**Query 4: Check for broken foreign key references**
```cypher
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE h.id <> p.host_id
RETURN count(*) AS broken_references;
```

**Expected:** `0` (no broken references)

---

**Query 5: Check RUNS_SERVICE relationships**
```cypher
MATCH (p:Port)-[r:RUNS_SERVICE]->(s:Service)
RETURN
  p.number AS port_number,
  type(r) AS relationship_type,
  s.name AS service_name,
  s.version AS service_version
LIMIT 10;
```

**Expected:** Services connected to their ports

---

**Query 6: Check BELONGS_TO for mission scoping**
```cypher
MATCH (h:Host)-[:BELONGS_TO]->(mr:MissionRun)
RETURN
  h.ip AS host_ip,
  mr.id AS mission_run_id,
  mr.mission_name AS mission_name
LIMIT 10;
```

**Expected:** Hosts linked to the mission run

---

**Query 7: Verify no orphaned ports**
```cypher
MATCH (p:Port)
WHERE NOT (()-[:HAS_PORT]->(p))
RETURN count(*) AS orphaned_ports;
```

**Expected:** `0` (all ports should have a parent host)

---

**Query 8: Verify no orphaned services**
```cypher
MATCH (s:Service)
WHERE NOT (()-[:RUNS_SERVICE]->(s))
RETURN count(*) AS orphaned_services;
```

**Expected:** `0` (all services should be connected to a port)

---

**Query 9: Full relationship path visualization**
```cypher
MATCH path = (mr:MissionRun)<-[:BELONGS_TO]-(h:Host)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
RETURN path
LIMIT 5;
```

**Expected:** Visual graph showing complete relationship chain

---

**Query 10: Count all entity types**
```cypher
MATCH (n)
RETURN
  labels(n)[0] AS entity_type,
  count(*) AS count
ORDER BY count DESC;
```

**Expected:** Counts for MissionRun, Host, Port, Service, etc.

---

**Query 11: Verify UUID format**
```cypher
MATCH (h:Host)
WHERE h.id =~ '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
RETURN count(*) AS valid_uuids, count(h) AS total_hosts;
```

**Expected:** `valid_uuids` should equal `total_hosts`

---

**Query 12: Check relationship counts**
```cypher
MATCH ()-[r]->()
RETURN
  type(r) AS relationship_type,
  count(*) AS count
ORDER BY count DESC;
```

**Expected:** Counts for HAS_PORT, RUNS_SERVICE, BELONGS_TO, etc.

---

### 8. Advanced Validation Queries

**Query 13: Verify taxonomy compliance (all required relationships exist)**
```cypher
// Every Port should have exactly one HAS_PORT incoming relationship
MATCH (p:Port)
WITH p, [(h:Host)-[:HAS_PORT]->(p) | h] AS hosts
WHERE size(hosts) <> 1
RETURN count(p) AS ports_with_wrong_parent_count;
```

**Expected:** `0` (every port has exactly one parent host)

---

**Query 14: Check for duplicate entities (same IP with different UUIDs)**
```cypher
MATCH (h:Host)
WITH h.ip AS ip, collect(h.id) AS uuids
WHERE size(uuids) > 1
RETURN ip, uuids, size(uuids) AS duplicate_count;
```

**Expected:** Empty result (no duplicates) OR minimal duplicates if rescans occurred

---

**Query 15: Verify bidirectional relationship integrity**
```cypher
// Every Port with host_id should have a matching HAS_PORT relationship
MATCH (p:Port)
WHERE p.host_id IS NOT NULL
OPTIONAL MATCH (h:Host {id: p.host_id})-[:HAS_PORT]->(p)
WITH p, h
WHERE h IS NULL
RETURN count(p) AS ports_with_missing_relationship;
```

**Expected:** `0` (all foreign keys have corresponding relationships)

---

## Expected Results Summary

After running all verification queries, you should see:

| Check | Expected Result |
|-------|----------------|
| Hosts with UUIDs | ✓ All hosts have valid UUID in `id` field |
| HAS_PORT relationships | ✓ All ports connected to parent hosts |
| Foreign key integrity | ✓ 100% of `port.host_id` matches `host.id` |
| RUNS_SERVICE relationships | ✓ Services connected to ports |
| BELONGS_TO relationships | ✓ Root entities linked to MissionRun |
| Orphaned ports | ✓ Zero orphaned ports |
| Orphaned services | ✓ Zero orphaned services |
| UUID format | ✓ All UUIDs match RFC 4122 format |
| Relationship counts | ✓ Non-zero counts for taxonomy relationships |
| Taxonomy compliance | ✓ Each entity has correct number of relationships |
| No duplicates | ✓ No duplicate entities (or minimal if rescanned) |
| Bidirectional integrity | ✓ Foreign keys match relationship existence |

## Common Issues and Debugging

### Issue: No data in Neo4j

**Symptoms:** All queries return 0 results

**Debug steps:**
```bash
# Check Gibson logs for errors
gibson mission run --verbose

# Verify Neo4j connection
docker logs neo4j-test | grep -i error

# Check if memory adapter is being used instead of Neo4j
grep -i "using.*adapter" gibson.log
```

### Issue: Orphaned nodes

**Symptoms:** Query 7 or 8 returns non-zero counts

**Debug steps:**
```cypher
// Find orphaned ports with their properties
MATCH (p:Port)
WHERE NOT (()-[:HAS_PORT]->(p))
RETURN p.number, p.host_id, p.id
LIMIT 10;

// Try to find the host by foreign key
MATCH (p:Port)
WHERE NOT (()-[:HAS_PORT]->(p))
OPTIONAL MATCH (h:Host {id: p.host_id})
RETURN p.number, p.host_id, h.ip
LIMIT 10;
```

**Resolution:** This indicates a bug in relationship creation logic. Check `StoreWithRelationships` implementation.

### Issue: Broken foreign keys

**Symptoms:** Query 4 returns non-zero count

**Debug steps:**
```cypher
// Find mismatched relationships
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE h.id <> p.host_id
RETURN h.ip, h.id AS host_id, p.number, p.host_id AS port_host_id
LIMIT 10;
```

**Resolution:** Bug in entity storage - foreign key not being set correctly.

### Issue: Duplicate entities

**Symptoms:** Query 14 returns multiple UUIDs for same IP

**Debug steps:**
```cypher
// Check timestamps to see if duplicates are from different runs
MATCH (h:Host)
WHERE h.ip = '192.168.1.1'  // Replace with duplicate IP
RETURN h.id, h.ip, h.discovered_at
ORDER BY h.discovered_at;
```

**Resolution:**
- If from same mission run: Bug in entity deduplication
- If from different runs: Expected behavior (different mission contexts)

## Cleanup

After testing is complete:

```bash
# Clear all test data from Neo4j
docker exec -it neo4j-test cypher-shell -u neo4j -p testpassword \
  "MATCH (n) DETACH DELETE n"

# Verify deletion
docker exec -it neo4j-test cypher-shell -u neo4j -p testpassword \
  "MATCH (n) RETURN count(n)"
# Should return: 0

# Stop and remove Neo4j container
docker stop neo4j-test
docker rm neo4j-test

# Remove test config files
rm /tmp/gibson-test-config.yaml
rm /tmp/test-mission.yaml
```

## Automated Test Script

For automated testing, see the companion script: `taxonomy_relationships_test.sh`

## References

- Gibson Framework: `/home/anthony/Code/zeroroot.ai/opensource/gibson/`
- Network-Recon Agent: `/home/anthony/Code/zeroroot.ai/enterprise/agents/network-recon/`
- Neo4j Adapter: `/home/anthony/Code/zeroroot.ai/opensource/sdk/memory/neo4j_adapter.go`
- Taxonomy Spec: `/home/anthony/Code/zeroroot.ai/.spec-workflow/specs/entity-taxonomy/`

## Next Steps

After validating the basic relationship structure:

1. Test with multiple mission runs (verify BELONGS_TO scoping)
2. Test with large datasets (performance testing)
3. Test relationship queries (e.g., "find all services on host X")
4. Test graph traversal performance
5. Test entity merging across missions
6. Validate GraphRAG integration

## Contributing

If you find issues with this test procedure or the implementation:

1. Create an issue in the Gibson repository
2. Include the failing query and expected vs. actual results
3. Attach relevant Gibson logs
4. Include Neo4j version and configuration
