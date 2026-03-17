# Gibson Authentication & Authorization

Gibson provides enterprise-grade authentication and authorization for securing the gRPC API. This document covers configuration, deployment, troubleshooting, and best practices.

## Table of Contents

- [Overview](#overview)
- [Supported Authentication Methods](#supported-authentication-methods)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Deployment Guides](#deployment-guides)
- [Client Authentication](#client-authentication)
- [Role-Based Access Control](#role-based-access-control)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)
- [Performance Tuning](#performance-tuning)

## Overview

Gibson authentication is built on industry-standard OpenID Connect (OIDC) with support for:

- **Enterprise SSO**: Okta, Azure AD, Google Workspace, Auth0
- **CI/CD Workload Identity**: GitHub Actions, GitLab CI, CircleCI
- **Kubernetes Integration**: ServiceAccount token validation via TokenReview API
- **Development Mode**: Static tokens for local development (not for production)

Authentication is **disabled by default** for backward compatibility. When enabled, all gRPC API calls require a valid Bearer token in the `authorization` metadata header.

## Supported Authentication Methods

### 1. OIDC Federation

Validate JWT tokens from OpenID Connect identity providers.

**Use Cases:**
- Human users authenticating via enterprise SSO
- Service accounts from identity providers
- Cross-organization federation

**Supported Providers:**
- Okta
- Azure AD / Microsoft Entra ID
- Google Workspace
- Auth0
- Any OIDC-compliant provider

### 2. GitHub Actions OIDC

Validate GitHub Actions OIDC tokens for CI/CD authentication.

**Use Cases:**
- GitHub Actions workflows executing missions
- Repository-specific access control
- Branch-based authorization

**Token Claims:**
- `repository`: Repository slug (e.g., `myorg/myrepo`)
- `ref`: Git ref (e.g., `refs/heads/main`)
- `workflow`: Workflow name
- `actor`: GitHub username who triggered the workflow

### 3. GitLab CI OIDC

Validate GitLab CI OIDC tokens for pipeline authentication.

**Use Cases:**
- GitLab CI/CD pipelines
- Project-specific access control
- Branch and environment-based authorization

**Token Claims:**
- `project_path`: GitLab project path (e.g., `myorg/myrepo`)
- `ref`: Git ref (e.g., `main`, `production`)
- `pipeline_source`: Pipeline source (push, web, schedule, api)
- `user_login`: GitLab username

### 4. Kubernetes ServiceAccounts

Validate Kubernetes ServiceAccount tokens via TokenReview API.

**Use Cases:**
- In-cluster workloads (ArgoCD, Tekton, custom controllers)
- Kubernetes-native RBAC integration
- Namespace-based authorization

**Token Information:**
- Namespace and ServiceAccount name extracted from TokenReview response
- Mapped to Gibson roles via namespace:serviceaccount format

### 5. Local Static Tokens

Static bearer tokens for local development.

**WARNING:** Never use in production! Tokens are stored in plaintext configuration.

**Use Cases:**
- Local development
- Testing
- Proof of concepts

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Client                              │
│  (CLI, CI/CD, Browser)                                     │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ Bearer Token
                  │ (authorization: Bearer <token>)
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│               gRPC Server (Gibson Daemon)                   │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │           Auth Interceptor                            │ │
│  │  1. Extract token from metadata                       │ │
│  │  2. Call Authenticator.Authenticate()                 │ │
│  │  3. Inject Identity into context                      │ │
│  └─────────────────┬─────────────────────────────────────┘ │
│                    │                                         │
│                    ▼                                         │
│  ┌───────────────────────────────────────────────────────┐ │
│  │      Composite Authenticator                          │ │
│  │  Try in order: OIDC → K8s → Local                    │ │
│  └─────────┬───────────────┬────────────┬────────────────┘ │
│            │               │            │                   │
│            ▼               ▼            ▼                   │
│  ┌─────────────┐  ┌────────────┐  ┌──────────┐           │
│  │   OIDC      │  │    K8s     │  │  Local   │           │
│  │ Validator   │  │ Validator  │  │Validator │           │
│  └──────┬──────┘  └──────┬─────┘  └─────┬────┘           │
│         │                │               │                  │
│         ▼                ▼               ▼                  │
│  ┌──────────┐    ┌────────────┐   ┌─────────┐            │
│  │  JWKS    │    │ TokenReview│   │  Static │            │
│  │  Cache   │    │    API     │   │  Tokens │            │
│  └──────────┘    └────────────┘   └─────────┘            │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐ │
│  │              Service Handlers                          │ │
│  │  - Access Identity via IdentityFromContext()          │ │
│  │  - Check permissions before executing actions         │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Basic Configuration

Enable authentication with default settings:

```yaml
# configs/gibson.yaml
auth:
  enabled: true
  trust_localhost: false  # Set to true to allow localhost without auth
  clock_skew: 30s         # Token expiry tolerance
```

### Enterprise SSO (Okta)

```yaml
auth:
  enabled: true
  oidc:
    - issuer: "https://your-company.okta.com"
      audience: "gibson-prod"
      jwks_ttl: 1h
      claims_mapping:
        groups: groups
        email: email
      role_bindings:
        security-admins: ["admin"]
        security-team: ["mission:execute", "findings:*"]
        developers: ["findings:read"]
```

### GitHub Actions

```yaml
auth:
  enabled: true
  oidc:
    - issuer: "https://token.actions.githubusercontent.com"
      audience: "https://github.com/your-org"
      jwks_ttl: 1h
      claims_mapping:
        repository: repo
        ref: branch
      role_bindings:
        # Repository + branch pattern
        "your-org/security-ci:refs/heads/main": ["mission:execute", "findings:export"]
        "your-org/security-ci:refs/heads/staging": ["mission:execute"]
        # Wildcard: all repos on main
        "your-org/*:refs/heads/main": ["findings:read"]
```

### GitLab CI

```yaml
auth:
  enabled: true
  oidc:
    - issuer: "https://gitlab.com"
      audience: "https://gitlab.com"
      jwks_ttl: 1h
      claims_mapping:
        project_path: project
        ref: branch
        pipeline_source: source
      role_bindings:
        "your-org/security-pipeline:main": ["mission:*"]
        "your-org/security-pipeline:staging": ["mission:execute"]
```

### Kubernetes ServiceAccounts

```yaml
auth:
  enabled: true
  kubernetes:
    enabled: true
    role_bindings:
      # Namespace:serviceaccount format
      "ci-cd:security-scanner": ["mission:execute"]
      "monitoring:findings-exporter": ["findings:*"]
      # Wildcards supported
      "ci-cd:*": ["findings:read"]              # All SAs in ci-cd namespace
      "*:gibson-admin": ["admin"]               # gibson-admin SA in any namespace
```

### Local Development

```yaml
auth:
  enabled: true
  trust_localhost: true  # Allow localhost without token
  local:
    users:
      - name: "dev"
        token: "dev-token-12345"
        roles: ["admin"]
```

## Deployment Guides

### Kubernetes with Okta

1. **Create Okta Application:**
   - Application Type: Web
   - Grant Types: Authorization Code, Refresh Token
   - Redirect URIs: Your application URIs
   - Assign Groups: security-admins, security-team

2. **Configure Gibson:**
   ```yaml
   auth:
     enabled: true
     oidc:
       - issuer: "https://your-company.okta.com"
         audience: "gibson-prod"
         claims_mapping:
           groups: groups
           email: email
         role_bindings:
           security-admins: ["admin"]
           security-team: ["mission:execute", "findings:*"]
   ```

3. **Deploy via Helm:**
   ```bash
   helm install gibson ./deploy/helm/gibson \
     --set config.auth.enabled=true \
     --set config.auth.oidc[0].issuer=https://your-company.okta.com \
     --set config.auth.oidc[0].audience=gibson-prod
   ```

### GitHub Actions

1. **Configure GitHub OIDC in Repository:**
   ```yaml
   # .github/workflows/security-scan.yml
   permissions:
     id-token: write    # Required for OIDC
     contents: read

   jobs:
     scan:
       runs-on: ubuntu-latest
       steps:
         - name: Get OIDC Token
           id: token
           run: |
             TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
               "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://github.com/your-org" | jq -r .value)
             echo "::set-output name=token::$TOKEN"

         - name: Execute Mission
           run: |
             grpcurl -H "authorization: Bearer ${{ steps.token.outputs.token }}" \
               gibson.example.com:443 gibson.DaemonService/RunMission
   ```

2. **Configure Gibson:**
   ```yaml
   auth:
     enabled: true
     oidc:
       - issuer: "https://token.actions.githubusercontent.com"
         audience: "https://github.com/your-org"
         claims_mapping:
           repository: repo
           ref: branch
         role_bindings:
           "your-org/security-ci:refs/heads/main": ["mission:execute"]
   ```

### Kubernetes ServiceAccounts

1. **Create ServiceAccount:**
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: security-scanner
     namespace: ci-cd
   ```

2. **Configure Gibson to accept ServiceAccount tokens:**
   ```yaml
   auth:
     enabled: true
     kubernetes:
       enabled: true
       role_bindings:
         "ci-cd:security-scanner": ["mission:execute"]
   ```

3. **Use token from pod:**
   ```bash
   TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
   grpcurl -H "authorization: Bearer $TOKEN" \
     gibson.default.svc.cluster.local:50002 \
     gibson.DaemonService/RunMission
   ```

## Client Authentication

### CLI

```bash
# Set token as environment variable
export GIBSON_TOKEN="your-jwt-token"

# Or pass explicitly
gibson mission run --token="your-jwt-token" workflow.yaml
```

### gRPC (grpcurl)

```bash
grpcurl \
  -H "authorization: Bearer your-jwt-token" \
  gibson.example.com:443 \
  gibson.DaemonService/Ping
```

### Go Client

```go
import (
    "context"
    "google.golang.org/grpc"
    "google.golang.org/grpc/metadata"
)

conn, err := grpc.Dial("gibson.example.com:443", grpc.WithTransportCredentials(creds))
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

// Add token to metadata
ctx := metadata.AppendToOutgoingContext(
    context.Background(),
    "authorization", "Bearer "+token,
)

// Make authenticated call
client := pb.NewDaemonServiceClient(conn)
resp, err := client.Ping(ctx, &pb.PingRequest{})
```

### Python Client

```python
import grpc

# Create channel with credentials
creds = grpc.ssl_channel_credentials()
channel = grpc.secure_channel('gibson.example.com:443', creds)

# Add auth metadata
metadata = [('authorization', f'Bearer {token}')]

# Make authenticated call
stub = daemon_pb2_grpc.DaemonServiceStub(channel)
response = stub.Ping(daemon_pb2.PingRequest(), metadata=metadata)
```

## Role-Based Access Control

### Role Naming Convention

Roles follow the pattern `resource:action`:

- `admin`: Full access to all resources
- `mission:execute`: Execute missions
- `mission:read`: Read mission status
- `mission:*`: All mission actions
- `findings:read`: Read findings
- `findings:export`: Export findings
- `findings:*`: All finding actions

### Wildcard Patterns

Role bindings support glob-style wildcards:

```yaml
role_bindings:
  # Exact match
  "security-team": ["mission:execute"]

  # Wildcard group name
  "security-*": ["findings:read"]

  # Repository wildcard (GitHub)
  "myorg/*:refs/heads/main": ["mission:execute"]

  # Namespace wildcard (K8s)
  "ci-cd:*": ["findings:read"]
  "*:admin": ["admin"]
```

### Permission Checking

Handlers can check permissions programmatically:

```go
identity, ok := auth.IdentityFromContext(ctx)
if !ok {
    return status.Error(codes.Unauthenticated, "not authenticated")
}

// Check specific permission
if err := auth.RequirePermission(ctx, "execute", "mission"); err != nil {
    return err  // Returns PERMISSION_DENIED status
}

// Or manually check
hasPermission := false
for _, role := range identity.Roles {
    if role == "admin" || role == "mission:execute" {
        hasPermission = true
        break
    }
}
```

## Troubleshooting

### Authentication Failures

**Problem:** `Unauthenticated: missing bearer token`

**Solution:**
- Ensure token is in `authorization` metadata header
- Format: `Bearer <token>` (note the space)
- Check client is setting gRPC metadata correctly

---

**Problem:** `Unauthenticated: invalid token signature`

**Solution:**
- Token signature doesn't match JWKS public key
- Check issuer configuration matches token's `iss` claim
- Verify JWKS endpoint is accessible
- Check token hasn't been tampered with

---

**Problem:** `Unauthenticated: token expired`

**Solution:**
- Token's `exp` claim is in the past
- Request a new token from identity provider
- Check clock skew configuration if clocks are misaligned
- Verify token lifetime is appropriate for use case

---

**Problem:** `Unauthenticated: unknown token issuer`

**Solution:**
- Token's `iss` claim doesn't match any configured issuer
- Add issuer to OIDC configuration
- Check for typos in issuer URL (trailing slash matters)
- Verify token is from expected identity provider

---

**Problem:** `Unauthenticated: invalid token audience`

**Solution:**
- Token's `aud` claim doesn't match configured audience
- Update audience configuration to match token
- Or request token with correct audience from IdP

### Permission Denied

**Problem:** `PermissionDenied: insufficient permissions`

**Solution:**
- User/service lacks required role
- Check role bindings configuration
- Verify claim values match binding patterns
- Review logs for role resolution details

### JWKS Fetching Issues

**Problem:** Slow authentication or timeouts

**Solution:**
- JWKS endpoint unreachable or slow
- Increase JWKS TTL to cache longer
- Check network connectivity to IdP
- Review metrics for cache hit rate

---

**Problem:** `failed to fetch JWKS`

**Solution:**
- JWKS endpoint unreachable
- Check `jwks_endpoint` configuration (or auto-discovery)
- Verify network allows outbound HTTPS to IdP
- Check IdP is operational

### Kubernetes TokenReview

**Problem:** `failed to validate token via TokenReview`

**Solution:**
- Gibson pod lacks RBAC permissions
- Create ClusterRole with `tokenreviews` create permission
- Bind to Gibson ServiceAccount
- Verify in-cluster config is accessible

## Security Best Practices

### 1. Never Disable Authentication in Production

Auth is disabled by default for backward compatibility. Always enable in production:

```yaml
auth:
  enabled: true
```

### 2. Use Short-Lived Tokens

Configure identity providers to issue short-lived tokens (1-24 hours). Use refresh tokens for long-running processes.

### 3. Rotate JWKS Keys Regularly

Configure identity providers to rotate signing keys periodically. Gibson's JWKS cache will automatically fetch updated keys.

### 4. Use Least Privilege Roles

Grant minimum required roles:

```yaml
# Good: Specific permissions
role_bindings:
  "developers": ["findings:read"]

# Bad: Overly broad permissions
role_bindings:
  "developers": ["admin"]
```

### 5. Audit Authentication Events

Enable audit logging to track:
- Successful authentications (subject, issuer, roles)
- Failed authentication attempts
- Permission denied events

Check logs regularly for suspicious activity.

### 6. Secure JWKS Endpoint

Ensure JWKS endpoints are:
- Served over HTTPS only
- Protected by rate limiting
- Monitored for availability

### 7. Use External Secrets in Kubernetes

Never store secrets in Helm values or ConfigMaps:

```yaml
# Bad
config:
  auth:
    local:
      users:
        - token: "hardcoded-token"  # Never do this!

# Good
externalSecrets:
  auth:
    enabled: true
    secretName: gibson-auth-tokens
```

### 8. Implement Network Policies

Restrict which pods can access Gibson gRPC API:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: gibson-access
spec:
  podSelector:
    matchLabels:
      app: gibson
  ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            access: gibson
```

### 9. Monitor Authentication Metrics

Track metrics to detect issues:
- `gibson_auth_attempts_total` (by issuer, result)
- `gibson_auth_latency_seconds` (by issuer)
- `gibson_jwks_cache_hits_total` (cache efficiency)

Alert on:
- High failure rate
- Latency spikes
- Low cache hit rate

### 10. Test Authentication in Staging

Always test authentication configuration in staging before production:

```bash
# Test with valid token
grpcurl -H "authorization: Bearer $VALID_TOKEN" \
  gibson-staging.example.com:443 gibson.DaemonService/Ping

# Test with invalid token (should fail)
grpcurl -H "authorization: Bearer invalid" \
  gibson-staging.example.com:443 gibson.DaemonService/Ping
```

## Performance Tuning

### JWKS Cache Tuning

Default JWKS TTL is 1 hour. Adjust based on your needs:

```yaml
auth:
  oidc:
    - issuer: "https://company.okta.com"
      jwks_ttl: 4h  # Cache for 4 hours
```

**Trade-offs:**
- Longer TTL: Better performance, delayed key rotation detection
- Shorter TTL: More IdP requests, faster key rotation

### Clock Skew Tolerance

Default clock skew is 30 seconds. Increase if systems have clock drift:

```yaml
auth:
  clock_skew: 60s  # Allow 1 minute clock skew
```

**Note:** Larger clock skew reduces security slightly by accepting expired tokens for longer.

### Connection Pooling

Gibson uses default HTTP connection pooling. For high-traffic deployments, tune the HTTP client:

```go
// In production code
http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 100
```

### Metrics and Monitoring

Monitor these metrics for performance insights:

```promql
# Authentication latency (should be < 10ms with cached JWKS)
histogram_quantile(0.99, gibson_auth_latency_seconds)

# Cache hit rate (should be > 95%)
rate(gibson_jwks_cache_hits_total{hit="true"}[5m]) /
rate(gibson_jwks_cache_hits_total[5m])

# Authentication failure rate
rate(gibson_auth_attempts_total{result="failure"}[5m])
```

---

## Support

For questions or issues:

- GitHub Issues: https://github.com/zero-day-ai/gibson/issues
- Documentation: https://docs.gibson.zero-day.ai
- Security Issues: security@zero-day.ai
