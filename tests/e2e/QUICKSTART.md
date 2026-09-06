# E2E Tests Quick Start Guide

Get up and running with Gibson's end-to-end tests in under 5 minutes.

## Prerequisites Check

```bash
# Check required tools
docker --version    # Should show Docker version 20.10+
go version          # Should show Go 1.21+
bash --version      # Should show Bash 4.0+

# Check API key is set
echo $ANTHROPIC_API_KEY  # Should show your API key
```

If any are missing, see [Prerequisites](#prerequisites) below.

## Run Your First Test (30 seconds)

```bash
# Navigate to tests directory
cd /home/anthony/Code/zeroroot.ai/opensource/gibson/tests/e2e

# Run automated test with cleanup
./taxonomy_relationships_test.sh --cleanup
```

That's it! The script will:
1. Start Neo4j in Docker
2. Build Gibson
3. Run a discovery mission
4. Verify relationships in Neo4j
5. Clean up everything

## Understanding the Output

### Success

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

### Failure

```
[ERROR] Found 3 broken foreign key references
[ERROR] Found 2 orphaned ports
[ERROR] SOME TESTS FAILED
```

If you see failures, see [Troubleshooting](#troubleshooting) below.

## Explore the Data (Manual Inspection)

If you want to inspect the data manually, run without cleanup:

```bash
# Run test and keep Neo4j running
./taxonomy_relationships_test.sh

# Open Neo4j Browser
open http://localhost:7474
# Login: neo4j / testpassword

# Run queries from cypher_queries_reference.md
```

### Essential Queries

Once in Neo4j Browser, try these queries:

```cypher
// See the graph visually
MATCH (n)
OPTIONAL MATCH (n)-[r]->(m)
RETURN n, r, m
LIMIT 50;

// Count entities
MATCH (n)
RETURN labels(n)[0] AS type, count(*) AS count
ORDER BY count DESC;

// See relationship paths
MATCH path = (h:Host)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
RETURN path
LIMIT 5;
```

For more queries, see `cypher_queries_reference.md`.

## Test Options

```bash
# Test against custom target
./taxonomy_relationships_test.sh --target 192.168.1.1 --cleanup

# Skip build (if Gibson already built)
./taxonomy_relationships_test.sh --skip-build --cleanup

# Verbose output (see full Gibson logs)
./taxonomy_relationships_test.sh --verbose --cleanup

# Keep environment for debugging
./taxonomy_relationships_test.sh
# Remember to clean up manually:
# docker stop neo4j-test-* && docker rm neo4j-test-*
```

## What's Being Tested?

The taxonomy relationships test validates:

- **UUID Identity** - Every entity has a unique UUID
- **Parent-Child Links** - Ports reference their host's UUID
- **Relationships** - HAS_PORT connects hosts to ports
- **No Orphans** - Every port has a parent host
- **Foreign Key Integrity** - 100% of foreign keys match relationships

### The Entity Graph

```
MissionRun
    ↓ BELONGS_TO
   Host (UUID: abc-123)
    ↓ HAS_PORT (host_id: abc-123)
   Port (UUID: def-456, host_id: abc-123)
    ↓ RUNS_SERVICE (port_id: def-456)
   Service (UUID: ghi-789, port_id: def-456)
```

## Next Steps

### 1. Read the Full Test Documentation

See `taxonomy_relationships_test.md` for:
- Detailed test procedure
- Manual verification steps
- Advanced queries
- Debugging procedures

### 2. Explore Cypher Queries

See `cypher_queries_reference.md` for:
- 50+ ready-to-use queries
- Integrity checks
- Graph traversal examples
- Performance queries

### 3. Run Tests in CI/CD

```yaml
# Example GitHub Actions
- name: E2E Tests
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    cd tests/e2e
    ./taxonomy_relationships_test.sh --cleanup
```

## Troubleshooting

### Test fails immediately

**Problem:** Docker not running or ports in use

**Solution:**
```bash
# Check Docker is running
docker ps

# Check ports are free
netstat -tuln | grep -E '7474|7687'

# Kill conflicting processes
docker stop $(docker ps -q --filter "name=neo4j")
```

### No data in Neo4j

**Problem:** Mission failed or used wrong adapter

**Solution:**
```bash
# Check mission logs
tail -f /tmp/gibson-mission-output.log

# Verify Neo4j connection
docker exec neo4j-test-* cypher-shell -u neo4j -p testpassword "RETURN 1"
```

### Foreign key integrity fails

**Problem:** Bug in relationship creation code

**Solution:**
```bash
# This indicates a code bug - file an issue with:
# 1. Test output
# 2. Gibson logs
# 3. Failed queries from Neo4j

# Debug query:
docker exec -it neo4j-test-* cypher-shell -u neo4j -p testpassword
```

```cypher
// Show mismatched relationships
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE h.id <> p.host_id
RETURN h.ip, h.id, p.number, p.host_id
LIMIT 10;
```

### Test is too slow

**Problem:** Target is slow or unreachable

**Solution:**
```bash
# Use faster target
./taxonomy_relationships_test.sh --target 127.0.0.1 --cleanup

# Or use scanme.nmap.org (default)
./taxonomy_relationships_test.sh --cleanup
```

## Prerequisites

### Install Docker

**Ubuntu/Debian:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

**macOS:**
```bash
brew install --cask docker
```

**Verify:**
```bash
docker run hello-world
```

### Install Go 1.21+

**Ubuntu/Debian:**
```bash
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

**macOS:**
```bash
brew install go
```

**Verify:**
```bash
go version
```

### Set API Key

```bash
# Add to ~/.bashrc or ~/.zshrc
export ANTHROPIC_API_KEY="your-api-key-here"

# Or set for current session
export ANTHROPIC_API_KEY="your-api-key-here"

# Verify
echo $ANTHROPIC_API_KEY
```

### Optional: Install cypher-shell

**Ubuntu/Debian:**
```bash
sudo apt-get install cypher-shell
```

**macOS:**
```bash
brew install cypher-shell
```

**Or use via Docker:**
```bash
alias cypher="docker exec -it neo4j-test cypher-shell -u neo4j -p testpassword"
```

## Common Commands

```bash
# Run test
./taxonomy_relationships_test.sh --cleanup

# Run test with custom target
./taxonomy_relationships_test.sh --target 10.0.0.1 --cleanup

# Skip build step
./taxonomy_relationships_test.sh --skip-build --cleanup

# Keep environment for inspection
./taxonomy_relationships_test.sh

# Connect to Neo4j
docker exec -it neo4j-test-* cypher-shell -u neo4j -p testpassword

# View Gibson logs
tail -f /tmp/gibson-mission-output.log

# Clean up manually
docker stop neo4j-test-* && docker rm neo4j-test-*
```

## Getting Help

- **Test Documentation:** `taxonomy_relationships_test.md`
- **Query Reference:** `cypher_queries_reference.md`
- **E2E Test Overview:** `README.md`
- **Gibson Documentation:** `/home/anthony/Code/zeroroot.ai/opensource/gibson/README.md`
- **Discord:** https://discord.gg/mkqd6mU3
- **Issues:** https://github.com/zeroroot-ai/gibson/issues

## Tips

1. **Always use --cleanup** in CI/CD to avoid port conflicts
2. **Use --skip-build** when iterating on tests (faster)
3. **Keep Neo4j running** when debugging (omit --cleanup)
4. **Use verbose mode** when test fails (--verbose)
5. **Check Gibson logs** at `/tmp/gibson-mission-output.log`

## Success Checklist

After your first successful test run, you should have:

- [ ] Neo4j started and accessible at http://localhost:7474
- [ ] Gibson built successfully
- [ ] Mission completed without errors
- [ ] All integrity checks passed
- [ ] No orphaned nodes or broken relationships
- [ ] Clean exit with "ALL TESTS PASSED"

If any step fails, see [Troubleshooting](#troubleshooting) above.

Happy testing!
