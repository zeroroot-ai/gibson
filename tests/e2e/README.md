# End-to-End Tests

This directory contains end-to-end test procedures and scripts for validating Gibson's functionality in real-world scenarios.

## Available Tests

### Taxonomy Relationships Test

**Purpose:** Validates UUID-based entity identity and taxonomy-driven relationship creation in Neo4j.

**Files:**
- `taxonomy_relationships_test.md` - Detailed test procedure with manual verification steps
- `taxonomy_relationships_test.sh` - Automated test script

**Quick Start:**

```bash
# Run automated test with cleanup
./taxonomy_relationships_test.sh --cleanup

# Run test against custom target
./taxonomy_relationships_test.sh --target 127.0.0.1 --cleanup

# Run test and keep environment for manual inspection
./taxonomy_relationships_test.sh

# Skip build step (if Gibson already built)
./taxonomy_relationships_test.sh --skip-build --cleanup

# Verbose output
./taxonomy_relationships_test.sh --verbose --cleanup
```

**What it tests:**
- UUID generation and uniqueness
- Parent-child relationships (Host → Port → Service)
- Foreign key integrity (port.host_id = host.id)
- Taxonomy relationship types (HAS_PORT, RUNS_SERVICE, BELONGS_TO)
- No orphaned nodes
- Relationship bidirectionality
- Mission scoping

**Expected duration:** 2-5 minutes

## Test Environment Requirements

### System Prerequisites

- **Docker** - For Neo4j test instance
- **Go 1.21+** - For building Gibson
- **Bash 4.0+** - For running test scripts
- **Network access** - To target (scanme.nmap.org or custom)

### Required Environment Variables

```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

### Optional Dependencies

- **cypher-shell** - For manual Neo4j queries (optional)
- **jq** - For JSON parsing in future tests (optional)

## Test Output

### Success Example

```
[INFO] Starting Neo4j Test Instance
[SUCCESS] Neo4j started successfully
[INFO] Building Gibson
[SUCCESS] Gibson built successfully
[INFO] Running Gibson Mission
[SUCCESS] Mission completed successfully
[INFO] Verifying Neo4j Relationships
[SUCCESS] Found 5 hosts
[SUCCESS] Found 12 HAS_PORT relationships
[SUCCESS] All 12 foreign keys are correct (100%)
[SUCCESS] No broken foreign key references
[SUCCESS] ALL TESTS PASSED
```

### Failure Example

```
[ERROR] Found 3 broken foreign key references
[ERROR] Found 2 orphaned ports
[ERROR] SOME TESTS FAILED
[WARNING] Check logs above for details
```

## Manual Testing

For detailed manual testing procedures, see `taxonomy_relationships_test.md`. This includes:

- Step-by-step setup instructions
- Comprehensive Cypher queries for verification
- Debugging procedures for common issues
- Visual graph queries for Neo4j Browser

## CI/CD Integration

To integrate these tests into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run E2E Taxonomy Test
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    cd tests/e2e
    ./taxonomy_relationships_test.sh --cleanup
```

## Troubleshooting

### Neo4j fails to start

```bash
# Check Docker logs
docker logs neo4j-test

# Verify ports are available
netstat -tuln | grep -E '7474|7687'
```

### No data in Neo4j after mission

**Common causes:**
1. Memory adapter used instead of Neo4j adapter
2. Neo4j connection failed (check config)
3. Mission failed before writing data

**Debug:**
```bash
# Check Gibson logs
cat /tmp/gibson-mission-output.log | grep -i neo4j

# Test Neo4j connectivity
docker exec neo4j-test cypher-shell -u neo4j -p testpassword "RETURN 1"
```

### Orphaned nodes found

**Indicates:** Bug in relationship creation logic

**Debug:**
```cypher
// Find orphaned ports
MATCH (p:Port)
WHERE NOT (()-[:HAS_PORT]->(p))
RETURN p.id, p.number, p.host_id
LIMIT 10;

// Try to find parent by foreign key
MATCH (p:Port)
WHERE NOT (()-[:HAS_PORT]->(p))
OPTIONAL MATCH (h:Host {id: p.host_id})
RETURN p.id, p.host_id, h.ip
LIMIT 10;
```

### UUID format validation fails

**Indicates:** Bug in UUID generation or storage

**Debug:**
```cypher
// Find invalid UUIDs
MATCH (h:Host)
WHERE NOT h.id =~ '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
RETURN h.id, h.ip
LIMIT 10;
```

## Contributing

When adding new E2E tests:

1. Create both a `.md` (manual) and `.sh` (automated) version
2. Follow the existing naming convention: `{feature}_test.{md,sh}`
3. Include comprehensive verification queries
4. Document expected results and common issues
5. Update this README with the new test

## References

- Gibson Framework: `/home/anthony/Code/zeroroot.ai/opensource/gibson/`
- SDK Documentation: `/home/anthony/Code/zeroroot.ai/opensource/sdk/README.md`
- Entity Taxonomy Spec: `/home/anthony/Code/zeroroot.ai/.spec-workflow/specs/entity-taxonomy/`

## Future Tests

Planned E2E tests:

- [ ] GraphRAG integration test
- [ ] Multi-agent coordination test
- [ ] Large dataset performance test
- [ ] Entity merging across missions
- [ ] Real-time graph updates test
- [ ] Distributed deployment test (Kubernetes)
