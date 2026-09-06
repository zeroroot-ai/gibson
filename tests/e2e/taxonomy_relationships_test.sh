#!/bin/bash
#
# End-to-End Taxonomy Relationships Test Script
#
# This script automates the validation of Gibson's UUID-based entity system
# and taxonomy-driven relationships in Neo4j.
#
# Usage:
#   ./taxonomy_relationships_test.sh [options]
#
# Options:
#   --target TARGET    Target to scan (default: scanme.nmap.org)
#   --cleanup          Clean up test environment after running
#   --skip-build       Skip building Gibson
#   --verbose          Enable verbose output
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TARGET="scanme.nmap.org"
CLEANUP=false
SKIP_BUILD=false
VERBOSE=false
NEO4J_PASSWORD="testpassword"
NEO4J_USER="neo4j"
NEO4J_CONTAINER="neo4j-test-$(date +%s)"
GIBSON_CONFIG="/tmp/gibson-test-config-$(date +%s).yaml"
MISSION_FILE="/tmp/test-mission-$(date +%s).yaml"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --cleanup)
            CLEANUP=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            grep '^#' "$0" | grep -v '#!/bin/bash' | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}==== $1 ====${NC}\n"
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking Prerequisites"

    local missing_deps=()

    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi

    if ! command -v go &> /dev/null; then
        missing_deps+=("go")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        exit 1
    fi

    if [ -z "$ANTHROPIC_API_KEY" ]; then
        log_warning "ANTHROPIC_API_KEY not set - some tests may fail"
    fi

    log_success "All prerequisites met"
}

# Start Neo4j
start_neo4j() {
    log_step "Starting Neo4j Test Instance"

    # Check if container already exists
    if docker ps -a | grep -q "$NEO4J_CONTAINER"; then
        log_warning "Container $NEO4J_CONTAINER already exists, removing..."
        docker rm -f "$NEO4J_CONTAINER" > /dev/null 2>&1 || true
    fi

    log_info "Starting Neo4j container: $NEO4J_CONTAINER"
    docker run -d \
        --name "$NEO4J_CONTAINER" \
        -p 7474:7474 \
        -p 7687:7687 \
        -e NEO4J_AUTH="$NEO4J_USER/$NEO4J_PASSWORD" \
        neo4j:latest > /dev/null

    log_info "Waiting for Neo4j to start..."
    local max_wait=60
    local waited=0
    while ! docker logs "$NEO4J_CONTAINER" 2>&1 | grep -q "Remote interface available"; do
        sleep 2
        waited=$((waited + 2))
        if [ $waited -gt $max_wait ]; then
            log_error "Neo4j failed to start within ${max_wait}s"
            docker logs "$NEO4J_CONTAINER"
            exit 1
        fi
    done

    log_success "Neo4j started successfully"
    log_info "Neo4j Browser: http://localhost:7474"
    log_info "Credentials: $NEO4J_USER / $NEO4J_PASSWORD"
}

# Build Gibson
build_gibson() {
    if [ "$SKIP_BUILD" = true ]; then
        log_step "Skipping Gibson Build"
        return
    fi

    log_step "Building Gibson"

    local gibson_dir="/home/anthony/Code/zero-day.ai/opensource/gibson"
    if [ ! -d "$gibson_dir" ]; then
        log_error "Gibson directory not found: $gibson_dir"
        exit 1
    fi

    cd "$gibson_dir"

    if [ "$VERBOSE" = true ]; then
        make build
    else
        make build > /dev/null 2>&1
    fi

    if [ ! -f "./bin/gibson" ]; then
        log_error "Gibson binary not found after build"
        exit 1
    fi

    log_success "Gibson built successfully"
    ./bin/gibson version || true
}

# Create test configuration
create_config() {
    log_step "Creating Test Configuration"

    cat > "$GIBSON_CONFIG" <<EOF
neo4j:
  uri: bolt://localhost:7687
  username: $NEO4J_USER
  password: $NEO4J_PASSWORD
  database: neo4j

llm:
  providers:
    - name: anthropic
      type: anthropic
      api_key: \${ANTHROPIC_API_KEY}

logging:
  level: info
  format: json
EOF

    log_success "Configuration created: $GIBSON_CONFIG"
}

# Create test mission
create_mission() {
    log_step "Creating Test Mission"

    cat > "$MISSION_FILE" <<EOF
apiVersion: gibson.zero-day.ai/v1
kind: Mission
metadata:
  name: taxonomy-relationship-test
  description: E2E test for UUID-based entities and taxonomy relationships

spec:
  target: $TARGET

  scope:
    in_scope:
      - $TARGET

  agents:
    - name: network-recon
      config:
        scan_type: quick
        port_range: "22,80,443,8080"
        max_hosts: 5

  llm_assignments:
    network-recon:
      primary:
        provider: anthropic
        model: claude-3-5-sonnet-20241022
        temperature: 0.0

  output:
    neo4j:
      enabled: true
      track_relationships: true
    findings:
      enabled: true
      format: json
EOF

    log_success "Mission created: $MISSION_FILE"
    log_info "Target: $TARGET"
}

# Run Gibson mission
run_mission() {
    log_step "Running Gibson Mission"

    local gibson_bin="/home/anthony/Code/zero-day.ai/opensource/gibson/bin/gibson"

    if [ "$VERBOSE" = true ]; then
        "$gibson_bin" mission run \
            --config "$GIBSON_CONFIG" \
            --mission "$MISSION_FILE"
    else
        "$gibson_bin" mission run \
            --config "$GIBSON_CONFIG" \
            --mission "$MISSION_FILE" \
            | tee /tmp/gibson-mission-output.log
    fi

    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Mission execution failed with exit code: $exit_code"
        exit $exit_code
    fi

    log_success "Mission completed successfully"
}

# Run Cypher query
run_query() {
    local query="$1"
    local description="$2"

    if [ -n "$description" ]; then
        log_info "Running: $description"
    fi

    docker exec -i "$NEO4J_CONTAINER" \
        cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        --format plain \
        <<< "$query"
}

# Verify relationships
verify_relationships() {
    log_step "Verifying Neo4j Relationships"

    # Give Neo4j a moment to finalize writes
    sleep 2

    local all_passed=true

    # Test 1: Check hosts with UUIDs
    log_info "Test 1: Hosts with UUIDs"
    local host_count=$(run_query "MATCH (h:Host) RETURN count(h) AS count;" "" | tail -n 1 | tr -d ' ')
    if [ "$host_count" -gt 0 ]; then
        log_success "Found $host_count hosts"
    else
        log_error "No hosts found in Neo4j"
        all_passed=false
    fi

    # Test 2: Verify HAS_PORT relationships exist
    log_info "Test 2: HAS_PORT relationships"
    local has_port_count=$(run_query "MATCH ()-[r:HAS_PORT]->() RETURN count(r) AS count;" "" | tail -n 1 | tr -d ' ')
    if [ "$has_port_count" -gt 0 ]; then
        log_success "Found $has_port_count HAS_PORT relationships"
    else
        log_warning "No HAS_PORT relationships found"
        all_passed=false
    fi

    # Test 3: Verify foreign key integrity
    log_info "Test 3: Foreign key integrity (port.host_id = host.id)"
    local correct_fks=$(run_query "MATCH (h:Host)-[:HAS_PORT]->(p:Port) WHERE h.id = p.host_id RETURN count(*) AS count;" "" | tail -n 1 | tr -d ' ')
    if [ "$correct_fks" -eq "$has_port_count" ]; then
        log_success "All $correct_fks foreign keys are correct (100%)"
    else
        log_error "Foreign key mismatch: $correct_fks correct out of $has_port_count"
        all_passed=false
    fi

    # Test 4: Check for broken foreign keys
    log_info "Test 4: Broken foreign key references"
    local broken_fks=$(run_query "MATCH (h:Host)-[:HAS_PORT]->(p:Port) WHERE h.id <> p.host_id RETURN count(*) AS count;" "" | tail -n 1 | tr -d ' ')
    if [ "$broken_fks" -eq 0 ]; then
        log_success "No broken foreign key references"
    else
        log_error "Found $broken_fks broken foreign key references"
        all_passed=false
    fi

    # Test 5: Check RUNS_SERVICE relationships
    log_info "Test 5: RUNS_SERVICE relationships"
    local runs_service_count=$(run_query "MATCH ()-[r:RUNS_SERVICE]->() RETURN count(r) AS count;" "" | tail -n 1 | tr -d ' ')
    if [ "$runs_service_count" -gt 0 ]; then
        log_success "Found $runs_service_count RUNS_SERVICE relationships"
    else
        log_info "No RUNS_SERVICE relationships found (may be expected if no services detected)"
    fi

    # Test 6: Check BELONGS_TO relationships
    log_info "Test 6: BELONGS_TO relationships"
    local belongs_to_count=$(run_query "MATCH ()-[r:BELONGS_TO]->() RETURN count(r) AS count;" "" | tail -n 1 | tr -d ' ')
    if [ "$belongs_to_count" -gt 0 ]; then
        log_success "Found $belongs_to_count BELONGS_TO relationships"
    else
        log_warning "No BELONGS_TO relationships found"
    fi

    # Test 7: Check for orphaned ports
    log_info "Test 7: Orphaned ports"
    local orphaned_ports=$(run_query "MATCH (p:Port) WHERE NOT (()-[:HAS_PORT]->(p)) RETURN count(*) AS count;" "" | tail -n 1 | tr -d ' ')
    if [ "$orphaned_ports" -eq 0 ]; then
        log_success "No orphaned ports"
    else
        log_error "Found $orphaned_ports orphaned ports"
        all_passed=false
    fi

    # Test 8: Check for orphaned services
    log_info "Test 8: Orphaned services"
    local orphaned_services=$(run_query "MATCH (s:Service) WHERE NOT (()-[:RUNS_SERVICE]->(s)) RETURN count(*) AS count;" "" | tail -n 1 | tr -d ' ')
    if [ "$orphaned_services" -eq 0 ]; then
        log_success "No orphaned services"
    else
        log_error "Found $orphaned_services orphaned services"
        all_passed=false
    fi

    # Test 9: Verify UUID format
    log_info "Test 9: UUID format validation"
    local valid_uuids=$(run_query "MATCH (h:Host) WHERE h.id =~ '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' RETURN count(*) AS count;" "" | tail -n 1 | tr -d ' ')
    if [ "$valid_uuids" -eq "$host_count" ]; then
        log_success "All $valid_uuids hosts have valid UUID format"
    else
        log_error "Invalid UUIDs found: $valid_uuids valid out of $host_count"
        all_passed=false
    fi

    # Test 10: Taxonomy compliance (each port has exactly one parent)
    log_info "Test 10: Taxonomy compliance"
    local wrong_parent_count=$(run_query "MATCH (p:Port) WITH p, [(h:Host)-[:HAS_PORT]->(p) | h] AS hosts WHERE size(hosts) <> 1 RETURN count(p) AS count;" "" | tail -n 1 | tr -d ' ')
    if [ "$wrong_parent_count" -eq 0 ]; then
        log_success "All ports have exactly one parent host"
    else
        log_error "Found $wrong_parent_count ports with wrong parent count"
        all_passed=false
    fi

    # Summary
    echo ""
    log_step "Test Summary"
    if [ "$all_passed" = true ]; then
        log_success "ALL TESTS PASSED"
        log_success "Entity counts:"
        log_info "  - Hosts: $host_count"
        log_info "  - Ports: $(run_query 'MATCH (p:Port) RETURN count(p) AS count;' '' | tail -n 1 | tr -d ' ')"
        log_info "  - Services: $(run_query 'MATCH (s:Service) RETURN count(s) AS count;' '' | tail -n 1 | tr -d ' ')"
        log_success "Relationship counts:"
        log_info "  - HAS_PORT: $has_port_count"
        log_info "  - RUNS_SERVICE: $runs_service_count"
        log_info "  - BELONGS_TO: $belongs_to_count"
        return 0
    else
        log_error "SOME TESTS FAILED"
        log_warning "Check logs above for details"
        return 1
    fi
}

# Cleanup function
cleanup() {
    log_step "Cleaning Up Test Environment"

    # Clear Neo4j data
    log_info "Clearing Neo4j data..."
    run_query "MATCH (n) DETACH DELETE n;" "Deleting all nodes" > /dev/null || true

    # Stop Neo4j container
    log_info "Stopping Neo4j container..."
    docker stop "$NEO4J_CONTAINER" > /dev/null 2>&1 || true
    docker rm "$NEO4J_CONTAINER" > /dev/null 2>&1 || true

    # Remove config files
    rm -f "$GIBSON_CONFIG" "$MISSION_FILE"

    log_success "Cleanup complete"
}

# Trap cleanup on exit if requested
if [ "$CLEANUP" = true ]; then
    trap cleanup EXIT
fi

# Main execution
main() {
    log_step "Gibson Taxonomy Relationships E2E Test"
    log_info "Target: $TARGET"
    log_info "Cleanup: $CLEANUP"
    log_info "Skip Build: $SKIP_BUILD"

    check_prerequisites
    start_neo4j
    build_gibson
    create_config
    create_mission
    run_mission
    verify_relationships

    local test_result=$?

    if [ "$CLEANUP" = false ]; then
        log_info ""
        log_info "Neo4j is still running at http://localhost:7474"
        log_info "Container: $NEO4J_CONTAINER"
        log_info "To clean up manually:"
        log_info "  docker stop $NEO4J_CONTAINER && docker rm $NEO4J_CONTAINER"
    fi

    exit $test_result
}

# Run main function
main
