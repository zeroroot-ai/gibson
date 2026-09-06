# Cypher Queries Reference

Quick reference for validating Gibson's taxonomy relationships in Neo4j.

## Connection

```bash
# Via Docker
docker exec -it neo4j-test cypher-shell -u neo4j -p testpassword

# Via cypher-shell (if installed locally)
cypher-shell -u neo4j -p testpassword -a bolt://localhost:7687
```

## Entity Queries

### Count all entity types

```cypher
MATCH (n)
RETURN labels(n)[0] AS entity_type, count(*) AS count
ORDER BY count DESC;
```

### List all hosts

```cypher
MATCH (h:Host)
RETURN h.id, h.ip, h.hostname, h.discovered_at
ORDER BY h.discovered_at DESC
LIMIT 20;
```

### List all ports

```cypher
MATCH (p:Port)
RETURN p.id, p.number, p.protocol, p.state, p.host_id
LIMIT 20;
```

### List all services

```cypher
MATCH (s:Service)
RETURN s.id, s.name, s.version, s.product, s.port_id
LIMIT 20;
```

### Find hosts with specific characteristics

```cypher
// Hosts with most ports
MATCH (h:Host)
OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
RETURN h.ip, count(p) AS port_count
ORDER BY port_count DESC
LIMIT 10;

// Hosts with specific ports open
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE p.number IN [22, 80, 443]
RETURN h.ip, collect(p.number) AS open_ports;

// Hosts running specific services
MATCH (h:Host)-[:HAS_PORT]->()-[:RUNS_SERVICE]->(s:Service)
WHERE s.name =~ '(?i)ssh|http|mysql'
RETURN h.ip, collect(DISTINCT s.name) AS services;
```

## Relationship Queries

### Count all relationship types

```cypher
MATCH ()-[r]->()
RETURN type(r) AS relationship_type, count(*) AS count
ORDER BY count DESC;
```

### Verify HAS_PORT relationships

```cypher
// Count HAS_PORT relationships
MATCH ()-[r:HAS_PORT]->()
RETURN count(r) AS has_port_count;

// Show HAS_PORT with details
MATCH (h:Host)-[r:HAS_PORT]->(p:Port)
RETURN h.ip, p.number, p.state
LIMIT 20;
```

### Verify RUNS_SERVICE relationships

```cypher
// Count RUNS_SERVICE relationships
MATCH ()-[r:RUNS_SERVICE]->()
RETURN count(r) AS runs_service_count;

// Show services running on ports
MATCH (p:Port)-[r:RUNS_SERVICE]->(s:Service)
RETURN p.number, s.name, s.version
LIMIT 20;
```

### Verify BELONGS_TO relationships

```cypher
// Show mission scoping
MATCH (h:Host)-[:BELONGS_TO]->(mr:MissionRun)
RETURN mr.mission_name, mr.id, count(h) AS host_count
ORDER BY mr.mission_name;

// Full scoping chain
MATCH (mr:MissionRun)<-[:BELONGS_TO]-(entity)
RETURN labels(entity)[0] AS entity_type, count(*) AS count;
```

### Full relationship paths

```cypher
// Complete entity chain
MATCH path = (mr:MissionRun)<-[:BELONGS_TO]-(h:Host)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
RETURN path
LIMIT 5;

// Visualize full graph structure
MATCH (n)
OPTIONAL MATCH (n)-[r]->(m)
RETURN n, r, m
LIMIT 100;
```

## Integrity Checks

### Foreign key integrity

```cypher
// Verify port.host_id matches host.id
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE h.id = p.host_id
RETURN count(*) AS correct_foreign_keys;

// Find broken foreign keys
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE h.id <> p.host_id
RETURN h.ip, h.id AS host_id, p.number, p.host_id AS port_host_id
LIMIT 10;
```

### Orphaned nodes

```cypher
// Find orphaned ports
MATCH (p:Port)
WHERE NOT (()-[:HAS_PORT]->(p))
RETURN count(p) AS orphaned_ports;

// Show orphaned port details
MATCH (p:Port)
WHERE NOT (()-[:HAS_PORT]->(p))
RETURN p.id, p.number, p.host_id
LIMIT 10;

// Find orphaned services
MATCH (s:Service)
WHERE NOT (()-[:RUNS_SERVICE]->(s))
RETURN count(s) AS orphaned_services;

// Find orphaned hosts (no BELONGS_TO)
MATCH (h:Host)
WHERE NOT (h)-[:BELONGS_TO]->()
RETURN count(h) AS orphaned_hosts;
```

### Taxonomy compliance

```cypher
// Every port should have exactly one parent host
MATCH (p:Port)
WITH p, [(h:Host)-[:HAS_PORT]->(p) | h] AS hosts
WHERE size(hosts) <> 1
RETURN p.id, p.number, size(hosts) AS parent_count;

// Every service should have exactly one parent port
MATCH (s:Service)
WITH s, [(p:Port)-[:RUNS_SERVICE]->(s) | p] AS ports
WHERE size(ports) <> 1
RETURN s.id, s.name, size(ports) AS parent_count;
```

### UUID validation

```cypher
// Check UUID format (RFC 4122)
MATCH (h:Host)
WHERE h.id =~ '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
RETURN count(h) AS valid_uuid_count;

// Find invalid UUIDs
MATCH (h:Host)
WHERE NOT h.id =~ '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
RETURN h.id, h.ip
LIMIT 10;

// Check for duplicate UUIDs (should be 0)
MATCH (h:Host)
WITH h.id AS uuid, count(*) AS occurrences
WHERE occurrences > 1
RETURN uuid, occurrences;
```

### Bidirectional integrity

```cypher
// Ports with foreign keys but no relationship
MATCH (p:Port)
WHERE p.host_id IS NOT NULL
  AND NOT (()-[:HAS_PORT]->(p))
RETURN count(p) AS ports_with_missing_relationship;

// Services with foreign keys but no relationship
MATCH (s:Service)
WHERE s.port_id IS NOT NULL
  AND NOT (()-[:RUNS_SERVICE]->(s))
RETURN count(s) AS services_with_missing_relationship;
```

## Duplicate Detection

```cypher
// Find duplicate hosts by IP
MATCH (h:Host)
WITH h.ip AS ip, collect(h.id) AS uuids
WHERE size(uuids) > 1
RETURN ip, uuids, size(uuids) AS duplicate_count
ORDER BY duplicate_count DESC;

// Find duplicate ports on same host
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WITH h.id AS host_id, p.number AS port_number, collect(p.id) AS port_ids
WHERE size(port_ids) > 1
RETURN host_id, port_number, port_ids, size(port_ids) AS duplicate_count;
```

## Graph Traversal Examples

### Find attack surface

```cypher
// All publicly exposed services
MATCH (h:Host)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
WHERE p.state = 'open'
  AND p.number IN [21, 22, 23, 25, 80, 443, 3306, 5432, 8080]
RETURN h.ip, p.number, s.name, s.version
ORDER BY h.ip, p.number;
```

### Find interesting targets

```cypher
// Hosts with admin interfaces
MATCH (h:Host)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
WHERE s.name =~ '(?i)admin|panel|dashboard|console'
RETURN h.ip, p.number, s.name;

// Hosts with outdated services
MATCH (h:Host)-[:HAS_PORT]->()-[:RUNS_SERVICE]->(s:Service)
WHERE s.version IS NOT NULL
  AND s.version =~ '(?i).*[0-9]+\.[0-9]+.*'
RETURN h.ip, s.name, s.version
ORDER BY s.name;

// Hosts with many open ports (potentially misconfigured)
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE p.state = 'open'
WITH h, count(p) AS open_ports
WHERE open_ports > 10
RETURN h.ip, open_ports
ORDER BY open_ports DESC;
```

### Network mapping

```cypher
// All unique services in the network
MATCH (s:Service)
RETURN DISTINCT s.name, count(*) AS instances
ORDER BY instances DESC;

// Port distribution
MATCH (p:Port)
WHERE p.state = 'open'
RETURN p.number, count(*) AS count
ORDER BY count DESC
LIMIT 20;

// Protocol distribution
MATCH (p:Port)
RETURN p.protocol, count(*) AS count
ORDER BY count DESC;
```

## Performance Queries

### Index usage

```cypher
// Show all indexes
CALL db.indexes();

// Show constraints
CALL db.constraints();
```

### Query performance

```cypher
// Profile a query (shows execution plan)
PROFILE
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
RETURN h.ip, count(p)
ORDER BY count(p) DESC
LIMIT 10;

// Explain a query (shows planned execution)
EXPLAIN
MATCH (h:Host)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
WHERE s.name = 'http'
RETURN h.ip, p.number;
```

### Database statistics

```cypher
// Total node count
MATCH (n)
RETURN count(n) AS total_nodes;

// Total relationship count
MATCH ()-[r]->()
RETURN count(r) AS total_relationships;

// Database size and statistics
//
// NOT AVAILABLE on a tenant Neo4j. The procedure allowlist admits
// apoc.merge.node and apoc.merge.relationship only (ADR-0012, gibson#1257),
// so every other APOC procedure — including this one — is unregistered and
// the call fails with "no procedure with the name ... registered". Use the
// node/relationship counts above, or SHOW INDEXES / SHOW CONSTRAINTS.
CALL apoc.meta.stats()
YIELD nodeCount, relCount, labelCount, relTypeCount
RETURN nodeCount, relCount, labelCount, relTypeCount;
```

## Maintenance Queries

### Clean up test data

```cypher
// Delete everything (USE WITH CAUTION!)
MATCH (n)
DETACH DELETE n;

// Delete specific mission data
MATCH (mr:MissionRun {id: 'mission-uuid'})
OPTIONAL MATCH (mr)<-[:BELONGS_TO]-(entity)
DETACH DELETE mr, entity;

// Delete orphaned nodes
MATCH (n)
WHERE NOT (n)--()
DELETE n;
```

### Export data

```cypher
// Export hosts to CSV format
MATCH (h:Host)
RETURN h.id, h.ip, h.hostname, h.discovered_at
ORDER BY h.discovered_at;

// Export relationships for analysis
MATCH (h:Host)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
RETURN h.ip AS host, p.number AS port, s.name AS service, s.version AS version
ORDER BY h.ip, p.number;
```

## Quick Validation Script

Copy-paste this into Neo4j Browser to run all integrity checks at once:

```cypher
// Complete integrity check
MATCH (h:Host)
WITH count(h) AS host_count
MATCH (p:Port)
WITH host_count, count(p) AS port_count
MATCH (s:Service)
WITH host_count, port_count, count(s) AS service_count
MATCH ()-[hp:HAS_PORT]->()
WITH host_count, port_count, service_count, count(hp) AS has_port_count
MATCH ()-[rs:RUNS_SERVICE]->()
WITH host_count, port_count, service_count, has_port_count, count(rs) AS runs_service_count
MATCH (h2:Host)-[:HAS_PORT]->(p2:Port)
WHERE h2.id = p2.host_id
WITH host_count, port_count, service_count, has_port_count, runs_service_count, count(*) AS correct_fks
MATCH (orphan_p:Port)
WHERE NOT (()-[:HAS_PORT]->(orphan_p))
WITH host_count, port_count, service_count, has_port_count, runs_service_count, correct_fks, count(orphan_p) AS orphaned_ports
MATCH (orphan_s:Service)
WHERE NOT (()-[:RUNS_SERVICE]->(orphan_s))
WITH host_count, port_count, service_count, has_port_count, runs_service_count, correct_fks, orphaned_ports, count(orphan_s) AS orphaned_services
RETURN
  host_count AS hosts,
  port_count AS ports,
  service_count AS services,
  has_port_count AS has_port_rels,
  runs_service_count AS runs_service_rels,
  correct_fks AS correct_foreign_keys,
  orphaned_ports,
  orphaned_services,
  CASE WHEN correct_fks = has_port_count AND orphaned_ports = 0 AND orphaned_services = 0
    THEN 'PASS ✓'
    ELSE 'FAIL ✗'
  END AS integrity_status;
```

## Tips

1. **Use LIMIT** - Always use `LIMIT` when exploring data to avoid overwhelming results
2. **Indexes** - Ensure indexes exist on frequently queried properties (id, ip, etc.)
3. **PROFILE** - Use `PROFILE` to understand query performance
4. **Transactions** - Large writes should be batched with `CALL {...} IN TRANSACTIONS`
5. **APOC** - Install APOC plugin for advanced graph algorithms and utilities

## References

- Neo4j Cypher Manual: https://neo4j.com/docs/cypher-manual/current/
- Neo4j Browser Guide: Type `:help` in Neo4j Browser
- APOC Documentation: https://neo4j.com/labs/apoc/
