# Remote Mission Execution Guide

This guide explains how to use Gibson's remote mission execution feature to run local mission files against remote Gibson daemons.

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [CI/CD Integration](#cicd-integration)
  - [GitLab CI](#gitlab-ci)
  - [GitHub Actions](#github-actions)
  - [Jenkins](#jenkins)
  - [CircleCI](#circleci)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)
- [Advanced Usage](#advanced-usage)

## Overview

Gibson's remote execution feature enables you to:

- Run local mission files against remote Gibson daemons
- Integrate Gibson into CI/CD pipelines without manual file copying
- Maintain mission definitions in version control while executing on dedicated infrastructure
- Test mission changes locally before deploying to production

The CLI automatically detects remote connections and transmits mission content inline via gRPC, eliminating the need for filesystem access on the remote daemon.

## How It Works

### Automatic Detection

The Gibson CLI uses the `GIBSON_DAEMON_ADDRESS` environment variable to determine whether you're connecting to a local or remote daemon:

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Local** | Sends file path to daemon, which reads from its filesystem | Development, single-machine deployments |
| **Remote** | Reads file locally and transmits content inline (up to 10MB) | CI/CD, distributed deployments, Kubernetes |

### Local vs Remote Addresses

The daemon is considered **remote** when `GIBSON_DAEMON_ADDRESS` is set to any value except:

```
# Local addresses (use file path)
<empty/unset>
localhost
localhost:<any-port>
127.0.0.1
127.0.0.1:<any-port>
::1
::1:<any-port>

# Remote addresses (use inline YAML)
remote-host
remote-host:50002
192.168.1.100:50002
gibson.example.com:50002
10.0.0.5:50002
```

### Force Inline Mode (Port-Forward Support)

When using `kubectl port-forward` to access a remote daemon, the address appears as `localhost:50002` but the daemon is actually remote and doesn't have filesystem access. Use the `GIBSON_FORCE_INLINE_YAML` environment variable to force inline mode:

```bash
# Port-forward to remote daemon
kubectl port-forward svc/gibson 50002:50002 -n gibson &

# Force inline YAML mode even though address is localhost
export GIBSON_DAEMON_ADDRESS="localhost:50002"
export GIBSON_FORCE_INLINE_YAML="true"

# Now mission files are sent inline to the remote daemon
gibson mission run ./missions/recon.yaml
```

| Environment Variable | Values | Description |
|---------------------|--------|-------------|
| `GIBSON_FORCE_INLINE_YAML` | `true`, `1` | Force inline YAML mode regardless of address |

### Architecture

```
┌──────────────┐                           ┌──────────────┐
│              │   GIBSON_DAEMON_ADDRESS   │              │
│  Local CLI   │◄──────────────────────────┤  Remote      │
│              │                           │  Daemon      │
│  - Reads     │                           │              │
│    local     │   gRPC: workflow_yaml     │  - Parses    │
│    mission   ├──────────────────────────►│    YAML      │
│    YAML      │   (inline content)        │  - Executes  │
│  - Transmits │                           │    mission   │
│    inline    │   Event Stream            │  - Returns   │
│              │◄──────────────────────────┤    events    │
└──────────────┘                           └──────────────┘
```

## Quick Start

### Connect to Remote Daemon

```bash
# Set the remote daemon address
export GIBSON_DAEMON_ADDRESS="gibson.internal.example.com:50002"

# Verify connectivity
gibson daemon status

# Run a local mission file
gibson mission run ./missions/recon.yaml --target my-app
```

### One-Line Execution

```bash
# Execute without persisting environment variable
GIBSON_DAEMON_ADDRESS=remote-host:50002 gibson mission run ./mission.yaml
```

### Docker Container

```bash
# Run Gibson CLI in container with remote daemon
docker run --rm \
  -v $(pwd)/missions:/missions \
  -e GIBSON_DAEMON_ADDRESS="gibson.example.com:50002" \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  ghcr.io/zero-day-ai/gibson:latest \
  mission run /missions/security-scan.yaml
```

## CI/CD Integration

### GitLab CI

Full-featured GitLab CI pipeline with target management and finding analysis:

```yaml
# .gitlab-ci.yml
variables:
  GIBSON_DAEMON_ADDRESS: "gibson.internal.example.com:50002"
  GIBSON_TARGET: "${CI_PROJECT_NAME}-${CI_COMMIT_REF_SLUG}"

stages:
  - setup
  - test
  - security
  - report

# Setup target configuration
setup-target:
  stage: setup
  image: ghcr.io/zero-day-ai/gibson:latest
  script:
    - |
      # Create or update target
      gibson target delete ${GIBSON_TARGET} || true
      gibson target add ${GIBSON_TARGET} \
        --type http_api \
        --url ${CI_ENVIRONMENT_URL} \
        --metadata project=${CI_PROJECT_NAME} \
        --metadata branch=${CI_COMMIT_REF_NAME} \
        --metadata commit=${CI_COMMIT_SHA}
  only:
    - main
    - merge_requests

# Run security missions
security-scan:
  stage: security
  image: ghcr.io/zero-day-ai/gibson:latest
  needs: [setup-target]
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
  script:
    # Run reconnaissance mission
    - gibson mission run ./gibson/missions/recon.yaml --target ${GIBSON_TARGET}

    # Run vulnerability scanning mission
    - gibson mission run ./gibson/missions/vuln-scan.yaml --target ${GIBSON_TARGET}

    # Run authentication testing mission
    - gibson mission run ./gibson/missions/auth-test.yaml --target ${GIBSON_TARGET}

    # Export findings
    - gibson finding export --format json > findings.json

    # Generate summary
    - |
      echo "Security Scan Results:"
      jq -r '.[] | "\(.severity | ascii_upcase): \(.title)"' findings.json || echo "No findings"

  artifacts:
    reports:
      junit: findings.json
    paths:
      - findings.json
    expire_in: 30 days
  only:
    - main
    - merge_requests

# Analyze findings and fail on critical issues
evaluate-findings:
  stage: report
  image: ghcr.io/zero-day-ai/gibson:latest
  needs: [security-scan]
  script:
    - |
      # Count findings by severity
      CRITICAL=$(jq '[.[] | select(.severity == "critical")] | length' findings.json)
      HIGH=$(jq '[.[] | select(.severity == "high")] | length' findings.json)
      MEDIUM=$(jq '[.[] | select(.severity == "medium")] | length' findings.json)
      LOW=$(jq '[.[] | select(.severity == "low")] | length' findings.json)

      echo "Findings Summary:"
      echo "  Critical: $CRITICAL"
      echo "  High: $HIGH"
      echo "  Medium: $MEDIUM"
      echo "  Low: $LOW"

      # Fail pipeline on critical findings
      if [ "$CRITICAL" -gt 0 ]; then
        echo "ERROR: Found $CRITICAL critical security findings!"
        exit 1
      fi

      # Warn on high findings
      if [ "$HIGH" -gt 3 ]; then
        echo "WARNING: Found $HIGH high severity findings"
      fi
  allow_failure: false
  only:
    - main
    - merge_requests
```

### GitHub Actions

Comprehensive GitHub Actions workflow with scheduled scans:

```yaml
# .github/workflows/gibson-security.yml
name: Gibson Security Testing

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # Daily security scans at 2 AM UTC
    - cron: '0 2 * * *'
  workflow_dispatch:
    inputs:
      mission:
        description: 'Mission file to run'
        required: false
        default: 'missions/full-scan.yaml'

env:
  GIBSON_DAEMON_ADDRESS: gibson.internal.example.com:50002

jobs:
  security-scan:
    runs-on: ubuntu-latest

    strategy:
      matrix:
        mission:
          - missions/recon.yaml
          - missions/api-security.yaml
          - missions/web-security.yaml
      fail-fast: false

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Gibson CLI
        run: |
          # Download latest Gibson release
          curl -L https://github.com/zero-day-ai/gibson/releases/latest/download/gibson-linux-amd64 \
            -o /usr/local/bin/gibson
          chmod +x /usr/local/bin/gibson
          gibson version

      - name: Configure target
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          TARGET_NAME="${{ github.repository }}-${{ github.ref_name }}"

          # Remove existing target if present
          gibson target delete "${TARGET_NAME}" || true

          # Create new target
          gibson target add "${TARGET_NAME}" \
            --type http_api \
            --url "${{ github.event.deployment.payload.web_url || 'https://example.com' }}"

      - name: Run Gibson mission
        id: gibson
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          TARGET_NAME="${{ github.repository }}-${{ github.ref_name }}"

          echo "Running mission: ${{ matrix.mission }}"
          gibson mission run ${{ matrix.mission }} \
            --target "${TARGET_NAME}" \
            --var "git_sha=${{ github.sha }}" \
            --var "git_ref=${{ github.ref }}"

      - name: Export findings
        if: always()
        run: |
          gibson finding export --format json > findings-${{ strategy.job-index }}.json
          gibson finding export --format markdown > findings-${{ strategy.job-index }}.md

      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: findings-${{ strategy.job-index }}
          path: |
            findings-*.json
            findings-*.md

      - name: Analyze findings
        if: always()
        run: |
          if [ ! -f "findings-${{ strategy.job-index }}.json" ]; then
            echo "No findings file generated"
            exit 0
          fi

          CRITICAL=$(jq '[.[] | select(.severity == "critical")] | length' findings-${{ strategy.job-index }}.json)
          HIGH=$(jq '[.[] | select(.severity == "high")] | length' findings-${{ strategy.job-index }}.json)

          echo "## Security Findings Summary" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "Mission: \`${{ matrix.mission }}\`" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "- Critical: $CRITICAL" >> $GITHUB_STEP_SUMMARY
          echo "- High: $HIGH" >> $GITHUB_STEP_SUMMARY

          if [ "$CRITICAL" -gt 0 ]; then
            echo "" >> $GITHUB_STEP_SUMMARY
            echo "⚠️ **CRITICAL FINDINGS DETECTED**" >> $GITHUB_STEP_SUMMARY
            exit 1
          fi

      - name: Comment on PR
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const findingsFile = 'findings-${{ strategy.job-index }}.md';

            if (!fs.existsSync(findingsFile)) {
              return;
            }

            const findings = fs.readFileSync(findingsFile, 'utf8');

            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## Gibson Security Scan Results\n\n${findings}`
            });
```

### Jenkins

Jenkins Pipeline with parallel mission execution:

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        GIBSON_DAEMON_ADDRESS = 'gibson.internal.example.com:50002'
        ANTHROPIC_API_KEY = credentials('anthropic-api-key')
        TARGET_NAME = "${env.JOB_NAME}-${env.BRANCH_NAME}"
    }

    stages {
        stage('Setup') {
            steps {
                script {
                    sh """
                        gibson target delete ${TARGET_NAME} || true
                        gibson target add ${TARGET_NAME} \
                          --type http_api \
                          --url ${env.APPLICATION_URL}
                    """
                }
            }
        }

        stage('Security Testing') {
            parallel {
                stage('Reconnaissance') {
                    steps {
                        sh 'gibson mission run missions/recon.yaml --target ${TARGET_NAME}'
                    }
                }

                stage('API Security') {
                    steps {
                        sh 'gibson mission run missions/api-test.yaml --target ${TARGET_NAME}'
                    }
                }

                stage('Web Security') {
                    steps {
                        sh 'gibson mission run missions/web-test.yaml --target ${TARGET_NAME}'
                    }
                }
            }
        }

        stage('Analyze Results') {
            steps {
                script {
                    sh 'gibson finding export --format json > findings.json'

                    def findings = readJSON file: 'findings.json'
                    def critical = findings.count { it.severity == 'critical' }
                    def high = findings.count { it.severity == 'high' }

                    echo "Critical findings: ${critical}"
                    echo "High findings: ${high}"

                    if (critical > 0) {
                        error("Found ${critical} critical security findings!")
                    }

                    if (high > 5) {
                        unstable("Found ${high} high severity findings")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'findings.json', fingerprint: true

            publishHTML([
                reportDir: '.',
                reportFiles: 'findings.json',
                reportName: 'Security Findings',
                allowMissing: false
            ])
        }

        failure {
            emailext(
                subject: "Security Scan Failed: ${env.JOB_NAME}",
                body: "Critical security findings detected. Review: ${env.BUILD_URL}",
                to: "${env.SECURITY_TEAM_EMAIL}"
            )
        }
    }
}
```

### CircleCI

CircleCI configuration with caching and orbs:

```yaml
# .circleci/config.yml
version: 2.1

orbs:
  gibson: zero-day-ai/gibson@1.0.0  # Custom orb (if available)

executors:
  gibson-executor:
    docker:
      - image: ghcr.io/zero-day-ai/gibson:latest

jobs:
  security-scan:
    executor: gibson-executor
    environment:
      GIBSON_DAEMON_ADDRESS: gibson.internal.example.com:50002
    steps:
      - checkout

      - run:
          name: Setup target
          command: |
            gibson target add ${CIRCLE_PROJECT_REPONAME}-${CIRCLE_BRANCH} \
              --type http_api \
              --url ${APPLICATION_URL}

      - run:
          name: Run security missions
          command: |
            gibson mission run missions/full-scan.yaml \
              --target ${CIRCLE_PROJECT_REPONAME}-${CIRCLE_BRANCH}

      - run:
          name: Export findings
          command: gibson finding export --format json > findings.json
          when: always

      - store_artifacts:
          path: findings.json
          destination: security-findings

      - run:
          name: Check findings
          command: |
            CRITICAL=$(jq '[.[] | select(.severity == "critical")] | length' findings.json)
            if [ "$CRITICAL" -gt 0 ]; then
              echo "Found $CRITICAL critical findings"
              exit 1
            fi

workflows:
  version: 2
  security-testing:
    jobs:
      - security-scan:
          context: gibson-credentials
          filters:
            branches:
              only:
                - main
                - develop
```

## Configuration

### Daemon Configuration for Remote Access

Configure the Gibson daemon to accept remote connections:

```yaml
# ~/.gibson/config.yaml (on daemon host)
daemon:
  # Listen on all interfaces (not just localhost)
  grpc_address: 0.0.0.0:50002

  # Optional: Enable TLS for encrypted connections
  tls:
    enabled: true
    cert_file: /path/to/server-cert.pem
    key_file: /path/to/server-key.pem
    # Optional: Client certificate authentication
    client_ca_file: /path/to/client-ca.pem

# Optional: Configure firewall or network policies
# Allow connections from CI/CD networks only
```

### Client Configuration

```bash
# Set remote daemon address
export GIBSON_DAEMON_ADDRESS="gibson.example.com:50002"

# Optional: Configure TLS client certificates
export GIBSON_TLS_CERT="/path/to/client-cert.pem"
export GIBSON_TLS_KEY="/path/to/client-key.pem"
export GIBSON_TLS_CA="/path/to/ca-cert.pem"
```

## Troubleshooting

### Connection Issues

#### Problem: Connection Refused

```bash
Error: failed to connect to remote daemon at remote-host:50002
```

**Diagnosis:**
```bash
# Check if daemon is running
ssh user@remote-host 'gibson daemon status'

# Test network connectivity
telnet remote-host 50002
# or
nc -zv remote-host 50002

# Check if port is listening
ssh user@remote-host 'netstat -tlnp | grep 50002'
```

**Solutions:**
1. Start the daemon: `gibson daemon start`
2. Configure daemon to listen on all interfaces (see Configuration section)
3. Check firewall rules:
   ```bash
   # Allow port 50002
   sudo ufw allow 50002/tcp
   ```
4. Verify daemon configuration:
   ```bash
   cat ~/.gibson/config.yaml | grep grpc_address
   ```

#### Problem: TLS Handshake Failure

```bash
Error: transport: authentication handshake failed
```

**Solutions:**
1. Verify TLS certificates are valid and not expired
2. Ensure certificate paths are correct
3. Check certificate CN/SAN matches hostname
4. Verify CA certificate is trusted

### Mission File Issues

#### Problem: File Size Limit Exceeded

```bash
Error: mission file exceeds 10MB limit
```

**Solutions:**
1. Split large missions into smaller missions
2. Remove unnecessary comments and documentation
3. Extract large data into separate configuration files
4. Deploy mission directly on daemon filesystem for very large missions:
   ```bash
   scp large-mission.yaml user@remote-host:/tmp/
   GIBSON_DAEMON_ADDRESS="" gibson mission run /tmp/large-mission.yaml
   ```

#### Problem: File Not Found

```bash
Error: failed to read mission file: no such file or directory
```

**Solutions:**
1. Use absolute paths:
   ```bash
   gibson mission run /home/user/missions/scan.yaml
   ```
2. Check current working directory:
   ```bash
   pwd
   ls -l missions/
   ```
3. Verify file permissions:
   ```bash
   chmod 644 missions/scan.yaml
   ```

#### Problem: Invalid YAML Syntax

```bash
Error: mission YAML parse error: yaml: line 45: could not find expected ':'
```

**Solutions:**
1. Validate YAML before running:
   ```bash
   gibson mission validate missions/scan.yaml
   ```
2. Use YAML linter:
   ```bash
   yamllint missions/scan.yaml
   ```
3. Common YAML issues:
   - Tabs instead of spaces (YAML requires spaces)
   - Incorrect indentation
   - Unquoted special characters
   - Missing colons or dashes

### Daemon Version Issues

#### Problem: Older Daemon Doesn't Support Inline YAML

```bash
Warning: Remote daemon may not support inline YAML transmission
Error: workflow file not found on daemon filesystem
```

**Solutions:**
1. Update daemon to latest version:
   ```bash
   ssh user@remote-host 'gibson daemon stop'
   scp gibson user@remote-host:/usr/local/bin/
   ssh user@remote-host 'gibson daemon start'
   ```
2. Temporarily copy mission file:
   ```bash
   scp mission.yaml user@remote-host:/tmp/
   gibson mission run /tmp/mission.yaml
   ```
3. Deploy missions via configuration management (Ansible, Puppet, etc.)

## Security Best Practices

### 1. Use TLS Encryption

Always enable TLS for remote connections to protect mission content and credentials:

```yaml
# Daemon configuration
daemon:
  grpc_address: 0.0.0.0:50002
  tls:
    enabled: true
    cert_file: /etc/gibson/certs/server.crt
    key_file: /etc/gibson/certs/server.key
    client_ca_file: /etc/gibson/certs/ca.crt  # For mTLS
```

### 2. Network Isolation

- Deploy Gibson daemon in private networks (VPC, internal subnets)
- Use VPN or SSH tunnels for external access
- Restrict access with firewall rules or security groups

```bash
# Example: SSH tunnel for secure access
ssh -L 50002:localhost:50002 user@remote-host
export GIBSON_DAEMON_ADDRESS="localhost:50002"
gibson mission run ./mission.yaml
```

### 3. Mutual TLS (mTLS)

Require client certificates for authentication:

```yaml
# Daemon configuration
daemon:
  tls:
    enabled: true
    cert_file: /etc/gibson/certs/server.crt
    key_file: /etc/gibson/certs/server.key
    client_ca_file: /etc/gibson/certs/ca.crt
    require_client_cert: true
```

### 4. Secret Management

Never hardcode secrets in mission files. Use environment variables or secret management systems:

```yaml
# mission.yaml - BAD
nodes:
  auth-test:
    agent: api-tester
    parameters:
      api_key: "hardcoded-secret-key"  # NEVER do this!

# mission.yaml - GOOD
nodes:
  auth-test:
    agent: api-tester
    parameters:
      api_key: "${API_KEY}"  # Use environment variable
```

In CI/CD:
```yaml
# GitLab CI
variables:
  API_KEY: $API_KEY  # From GitLab CI/CD variables (masked)

# GitHub Actions
env:
  API_KEY: ${{ secrets.API_KEY }}  # From GitHub secrets
```

### 5. Audit Logging

Enable audit logging to track mission execution:

```yaml
# config.yaml
logging:
  level: info
  audit:
    enabled: true
    file: /var/log/gibson/audit.log
    include_mission_content: false  # Don't log mission YAML (may contain secrets)
```

### 6. Rate Limiting

Protect against abuse with rate limiting:

```yaml
# config.yaml
daemon:
  rate_limit:
    enabled: true
    max_missions_per_minute: 10
    max_missions_per_hour: 100
```

## Advanced Usage

### Custom Headers and Metadata

Pass custom metadata with missions:

```bash
gibson mission run ./mission.yaml \
  --target my-app \
  --var "environment=production" \
  --var "team=security" \
  --metadata "requester=ci-pipeline" \
  --metadata "ticket=SEC-1234"
```

### Mission Templating

Use environment variables for dynamic missions:

```yaml
# mission.yaml
name: "Dynamic Security Scan - ${ENVIRONMENT}"
description: "Scan ${TARGET_URL} in ${ENVIRONMENT} environment"

nodes:
  scan:
    agent: web-scanner
    parameters:
      target_url: "${TARGET_URL}"
      depth: "${SCAN_DEPTH:-3}"  # Default value: 3
      timeout: "${SCAN_TIMEOUT:-300}"
```

Run with variables:
```bash
export ENVIRONMENT="staging"
export TARGET_URL="https://staging.example.com"
export SCAN_DEPTH="5"
gibson mission run ./mission.yaml
```

### Multiple Daemon Support

Manage multiple remote daemons:

```bash
# Production daemon
export GIBSON_DAEMON_PROD="gibson-prod.example.com:50002"

# Staging daemon
export GIBSON_DAEMON_STAGING="gibson-staging.example.com:50002"

# Development daemon
export GIBSON_DAEMON_DEV="gibson-dev.example.com:50002"

# Run against specific environment
GIBSON_DAEMON_ADDRESS=$GIBSON_DAEMON_STAGING gibson mission run ./mission.yaml
```

### Batch Mission Execution

Execute multiple missions in sequence:

```bash
#!/bin/bash
# run-security-suite.sh

set -e

MISSIONS=(
  "missions/01-recon.yaml"
  "missions/02-discovery.yaml"
  "missions/03-vulnerability-scan.yaml"
  "missions/04-exploitation.yaml"
  "missions/05-reporting.yaml"
)

export GIBSON_DAEMON_ADDRESS="gibson.example.com:50002"
TARGET="my-application"

echo "Running security suite against: $TARGET"

for mission in "${MISSIONS[@]}"; do
  echo "Executing: $mission"
  gibson mission run "$mission" --target "$TARGET"

  # Wait for mission to complete
  sleep 2
done

echo "Security suite complete!"
gibson finding export --format json > findings-$(date +%Y%m%d).json
```

### Health Checks and Monitoring

Verify daemon health in automation:

```bash
#!/bin/bash
# check-daemon-health.sh

export GIBSON_DAEMON_ADDRESS="gibson.example.com:50002"

# Check daemon status
if ! gibson daemon status > /dev/null 2>&1; then
  echo "ERROR: Daemon is not responding"
  exit 1
fi

# Check component health
STATUS=$(gibson daemon status --format json)

if echo "$STATUS" | jq -e '.redis.healthy == false' > /dev/null; then
  echo "ERROR: Redis is unhealthy"
  exit 1
fi

if echo "$STATUS" | jq -e '.neo4j.healthy == false' > /dev/null; then
  echo "WARNING: Neo4j is unhealthy (non-critical)"
fi

echo "Daemon is healthy and ready"
exit 0
```

## Additional Resources

- [Gibson Documentation](https://github.com/zero-day-ai/gibson)
- [Gibson SDK](https://github.com/zero-day-ai/sdk)
- [Example Missions](https://github.com/zero-day-ai/gibson/tree/main/examples/missions)
- [CI/CD Templates](https://github.com/zero-day-ai/gibson/tree/main/examples/ci-cd)

## Support

For issues or questions:
- GitHub Issues: https://github.com/zero-day-ai/gibson/issues
- Documentation: https://docs.zero-day.ai/gibson
