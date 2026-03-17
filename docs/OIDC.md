# OIDC Architecture

This document details the OpenID Connect (OIDC) authentication architecture in Gibson, explaining why it's built directly into the daemon rather than delegated to infrastructure, and how all the components fit together.

## Why OIDC is Built Into Gibson

### The Problem With External Auth

| Approach | Limitation |
|----------|------------|
| **Istio/Linkerd JWT validation** | Binary yes/no - can't do "user X can run mission Y against target Z" |
| **oauth2-proxy** | HTTP-only, poor gRPC streaming support |
| **Envoy ext_authz** | Another component, can't access Gibson's mission/target context |
| **API Gateway** | Adds latency, can't do fine-grained RBAC |

### What Gibson Needs

```
Can [this identity] perform [this action] on [this resource] with [this scope]?

Examples:
- Can security-team execute mission api-scan against *.internal.com?
- Can github.com/myorg/app:main run vuln-scan against app.example.com?
- Can ci-cd:security-scanner read findings from any mission?
```

This requires **application-level authorization** that understands Gibson's domain model. External auth can only answer "is this token valid?" - not "should this token be allowed to do this specific thing?"

### The Architecture Decision

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL BOUNDARY                                │
│                                                                          │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐   │
│   │ User CLI │  │ CI/CD    │  │ K8s      │  │ API Clients          │   │
│   │          │  │ Pipeline │  │ Workload │  │                      │   │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────────┬───────────┘   │
│        │             │             │                    │              │
│        │ OIDC JWT    │ OIDC JWT    │ SA Token          │ OIDC JWT     │
│        └─────────────┴─────────────┴────────────────────┘              │
│                                    │                                    │
│                                    ▼                                    │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                      GIBSON DAEMON                              │   │
│   │  ┌──────────────────────────────────────────────────────────┐  │   │
│   │  │                 gRPC Auth Interceptor                     │  │   │
│   │  │                                                           │  │   │
│   │  │  1. Extract Bearer token from metadata                    │  │   │
│   │  │  2. Route to appropriate validator (OIDC/K8s/Local)       │  │   │
│   │  │  3. Validate signature, expiry, issuer, audience          │  │   │
│   │  │  4. Extract claims → map to Identity                      │  │   │
│   │  │  5. Resolve roles from bindings                           │  │   │
│   │  │  6. Inject Identity into request context                  │  │   │
│   │  │  7. Handlers call RequirePermission() as needed           │  │   │
│   │  └──────────────────────────────────────────────────────────┘  │   │
│   │                              │                                  │   │
│   │                              ▼                                  │   │
│   │  ┌──────────────────────────────────────────────────────────┐  │   │
│   │  │              Mission / Agent / Finding Handlers           │  │   │
│   │  │                                                           │  │   │
│   │  │  // In handler:                                           │  │   │
│   │  │  identity, _ := auth.IdentityFromContext(ctx)             │  │   │
│   │  │  if err := auth.RequirePermission(ctx,                    │  │   │
│   │  │      "execute", "mission"); err != nil {                  │  │   │
│   │  │      return nil, err // 403 PERMISSION_DENIED             │  │   │
│   │  │  }                                                        │  │   │
│   │  └──────────────────────────────────────────────────────────┘  │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│                         INTERNAL BOUNDARY                                │
│                                                                          │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐                              │
│   │  Agent   │  │   Tool   │  │  Plugin  │                              │
│   │   Pod    │  │  Worker  │  │   Pod    │                              │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘                              │
│        │             │             │                                     │
│        │   gRPC + NetworkPolicy (no OIDC overhead)                      │
│        └─────────────┴─────────────┘                                     │
│                      │                                                   │
│                      ▼                                                   │
│              Gibson Daemon                                               │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

**Key insight**: External clients use OIDC. Internal agent↔daemon communication uses NetworkPolicy (and optionally mTLS via service mesh) with zero auth overhead.

## Component Architecture

### Package Structure

```
internal/auth/
├── auth.go           # Authenticator interface, Identity struct
├── config.go         # AuthConfig, OIDCIssuerConfig, RoleBinding
├── errors.go         # Auth error types with gRPC status codes
├── interceptor.go    # gRPC unary/stream interceptors
├── oidc.go           # OIDC JWT validator
├── jwks.go           # JWKS cache with background refresh
├── claims.go         # Provider-specific claims normalization
├── roles.go          # Role binding and permission computation
├── k8s.go            # Kubernetes TokenReview validator
├── local.go          # Static token validator (dev mode)
├── composite.go      # Multi-strategy authenticator
├── metrics.go        # Prometheus metrics
├── audit.go          # Structured audit logging
└── doc.go            # Package documentation
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           TOKEN VALIDATION FLOW                          │
└─────────────────────────────────────────────────────────────────────────┘

  Token                                                           Identity
    │                                                                 ▲
    ▼                                                                 │
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│ Extract │───▶│  Route  │───▶│Validate │───▶│  Map    │───▶│ Resolve │
│ Bearer  │    │  to     │    │  JWT    │    │ Claims  │    │  Roles  │
│ Token   │    │Validator│    │         │    │         │    │         │
└─────────┘    └─────────┘    └─────────┘    └─────────┘    └─────────┘
                   │
          ┌────────┼────────┐
          ▼        ▼        ▼
      ┌──────┐ ┌──────┐ ┌──────┐
      │ OIDC │ │ K8s  │ │Local │
      │      │ │Token │ │      │
      │      │ │Review│ │      │
      └──────┘ └──────┘ └──────┘
```

### JWKS Caching

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           JWKS CACHE ARCHITECTURE                        │
└─────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │   JWKS Cache    │
                              │                 │
                              │ ┌─────────────┐ │
           GetKey(issuer,kid) │ │ issuer →    │ │
    Token ──────────────────▶ │ │   keys map  │ │ ───▶ Public Key
  Validation                  │ │   + expiry  │ │
                              │ └─────────────┘ │
                              │                 │
                              │   TTL: 1 hour   │
                              │   (default)     │
                              └────────┬────────┘
                                       │
                                       │ Cache Miss or Expired
                                       ▼
                              ┌─────────────────┐
                              │  HTTP Fetch     │
                              │                 │
                              │ GET {issuer}/   │
                              │ .well-known/    │
                              │ jwks.json       │
                              └─────────────────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │  Background     │
                              │  Refresh        │
                              │                 │
                              │  Runs at 75%    │
                              │  of TTL         │
                              └─────────────────┘
```

**Cache behavior:**
- Keys cached per-issuer with configurable TTL (default 1 hour)
- Background refresh at 75% TTL prevents blocking requests
- Graceful degradation: uses stale cache if refresh fails
- Thread-safe with `sync.RWMutex`

### Role Binding Resolution

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ROLE BINDING RESOLUTION                          │
└─────────────────────────────────────────────────────────────────────────┘

  Identity Claims                     Role Bindings                   Permissions
  ┌─────────────┐                    ┌──────────────┐               ┌───────────┐
  │ groups:     │                    │ security-*:  │               │ mission:  │
  │ - security- │   ────matches────▶ │   [admin]    │ ───expands──▶ │   execute │
  │   admins    │                    │              │               │   *:*     │
  │             │                    │ developers:  │               │           │
  │ repository: │   ────matches────▶ │   [read]     │ ───expands──▶ │ findings: │
  │ myorg/app   │                    │              │               │   read    │
  │             │                    │ myorg/*:main │               │           │
  │ ref: main   │   ────matches────▶ │   [deploy]   │ ───expands──▶ │ mission:  │
  └─────────────┘                    └──────────────┘               │   execute │
                                                                    │ scope:    │
                                                                    │   app.*   │
                                                                    └───────────┘

  Matching patterns:
  - Exact: "security-admins" matches "security-admins"
  - Wildcard: "security-*" matches "security-admins", "security-team"
  - Repo:ref: "myorg/app:main" matches repository + ref claims
  - Namespace:SA: "ci-cd:scanner" matches K8s identity
```

## Configuration Reference

### Minimal Configuration

```yaml
# Auth disabled (default) - all requests allowed
auth:
  enabled: false
```

### Production Configuration

```yaml
auth:
  enabled: true
  clock_skew: 30s        # Token expiry tolerance
  trust_localhost: false # Never in production

  oidc:
    - issuer: https://company.okta.com
      audience: gibson-prod
      jwks_ttl: 1h
      claims_mapping:
        groups: groups
        email: email
      role_bindings:
        "security-admins": ["admin"]
        "security-team": ["mission:execute", "findings:*"]
        "developers": ["findings:read"]
```

### Full Configuration

```yaml
auth:
  # Master switch - when false, all requests allowed
  enabled: true

  # Clock skew tolerance for token expiry validation
  # Handles minor time drift between IdP and Gibson
  clock_skew: 30s

  # Skip auth for localhost connections (dev only)
  # Creates synthetic admin identity for 127.0.0.1/::1
  trust_localhost: false

  # OIDC providers (tried in order)
  oidc:
    # Enterprise IdP
    - issuer: https://company.okta.com
      audience: gibson-prod
      jwks_endpoint: ""           # Auto-discovered from issuer
      jwks_ttl: 1h                # How long to cache JWKS

      # Map token claims to identity fields
      claims_mapping:
        groups: groups            # Token claim → Identity.Groups
        email: email              # Token claim → Identity.Email

      # Map claim values to Gibson roles
      role_bindings:
        # Group-based
        "security-admins": ["admin"]
        "security-team": ["mission:execute", "findings:*"]
        "developers": ["findings:read"]

        # Wildcard patterns
        "security-*": ["findings:read"]

    # GitHub Actions
    - issuer: https://token.actions.githubusercontent.com
      audience: sts.amazonaws.com
      claims_mapping:
        repository: repo
        ref: branch
      role_bindings:
        # repo:branch format
        "myorg/infra:refs/heads/main": ["mission:execute", "admin"]
        "myorg/app:refs/heads/main": ["mission:execute"]
        "myorg/*:refs/heads/main": ["findings:read"]

    # GitLab CI
    - issuer: https://gitlab.com
      claims_mapping:
        project_path: project
        ref: branch
      role_bindings:
        "myorg/security-pipelines:main": ["mission:*"]

  # Kubernetes ServiceAccount validation
  kubernetes:
    enabled: true
    role_bindings:
      # namespace:serviceaccount format
      "ci-cd:security-scanner": ["mission:execute"]
      "ci-cd:*": ["findings:read"]
      "gibson:*": ["admin"]  # Gibson namespace has full access

  # Local static tokens (development only)
  local:
    users:
      - name: dev
        token: dev-token-12345
        roles: ["admin"]
      - name: readonly
        token: readonly-token
        roles: ["findings:read"]
```

### Role Syntax

Roles follow the pattern `resource:action` or `resource:action:scope`:

| Role | Meaning |
|------|---------|
| `admin` | Full access to everything |
| `mission:execute` | Can execute missions |
| `mission:*` | All mission operations |
| `findings:read` | Can read findings |
| `findings:*` | All findings operations |
| `*:read` | Read any resource |
| `mission:execute:*.internal.com` | Execute missions scoped to internal |

### Environment Variables

Configuration can be overridden via environment:

| Variable | Description |
|----------|-------------|
| `GIBSON_AUTH_ENABLED` | Enable/disable auth |
| `GIBSON_AUTH_TRUST_LOCALHOST` | Allow localhost bypass |
| `GIBSON_AUTH_CLOCK_SKEW` | Token expiry tolerance |

## Observability

### Prometheus Metrics

```
# Authentication attempts
gibson_auth_attempts_total{issuer="okta.com", result="success"}
gibson_auth_attempts_total{issuer="okta.com", result="invalid_token"}
gibson_auth_attempts_total{issuer="okta.com", result="expired"}
gibson_auth_attempts_total{issuer="github", result="permission_denied"}

# Authentication latency
gibson_auth_latency_seconds{issuer="okta.com", quantile="0.5"}
gibson_auth_latency_seconds{issuer="okta.com", quantile="0.99"}

# JWKS cache
gibson_jwks_cache_hits_total{issuer="okta.com", hit="true"}
gibson_jwks_cache_hits_total{issuer="okta.com", hit="false"}

# Permission denied
gibson_auth_permission_denied_total{action="execute", resource="mission"}
```

### OpenTelemetry Tracing

Auth decisions add span attributes:

```
auth.authenticated: true
auth.subject: "user@company.com"
auth.issuer: "https://company.okta.com"
auth.roles: ["mission:execute", "findings:read"]
auth.groups: ["security-team"]
auth.permissions_count: 3
```

### Audit Logging

Structured JSON logs for compliance:

```json
{
  "level": "INFO",
  "msg": "authentication audit event",
  "event_type": "authentication_success",
  "timestamp": "2026-03-17T10:00:00Z",
  "method": "/gibson.DaemonService/ExecuteMission",
  "subject": "user@company.com",
  "issuer": "https://company.okta.com",
  "roles": ["mission:execute"],
  "trace_id": "abc123"
}
```

```json
{
  "level": "WARN",
  "msg": "authentication audit event",
  "event_type": "permission_denied",
  "timestamp": "2026-03-17T10:00:01Z",
  "method": "/gibson.DaemonService/DeleteMission",
  "subject": "readonly@company.com",
  "action": "delete",
  "resource": "mission",
  "reason": "insufficient permissions"
}
```

## Security Considerations

### Token Handling

- Tokens are **never logged**, even at debug level
- Tokens are **never stored** - validated on each request
- Failed auth attempts are rate-limited via the issuer's JWKS endpoint caching

### JWKS Security

- JWKS endpoints **must use HTTPS**
- Keys are validated against the `kid` (key ID) header
- Only RSA and ECDSA signatures supported (no HMAC/shared secrets)

### Localhost Bypass

When `trust_localhost: true`:
- Connections from `127.0.0.1`, `::1`, or `localhost` get a synthetic admin identity
- **Never enable in production** - exists only for local development
- Logged as `event_type: localhost_bypass` for audit

### Internal Communication

Agent↔daemon communication does **not** use OIDC:
- Secured by Kubernetes NetworkPolicy (only `gibson` namespace can reach daemon)
- Optionally add mTLS via Istio/Linkerd
- Zero token validation overhead for internal calls

## Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `UNAUTHENTICATED: missing bearer token` | No Authorization header | Add `authorization: Bearer <token>` to gRPC metadata |
| `UNAUTHENTICATED: unknown issuer` | Token issuer not in config | Add issuer to `auth.oidc` list |
| `UNAUTHENTICATED: token expired` | Token past expiry | Get fresh token, check clock sync |
| `UNAUTHENTICATED: invalid signature` | Wrong signing key | Check JWKS endpoint, clear cache |
| `PERMISSION_DENIED: insufficient permissions` | Missing role binding | Add appropriate role binding |

### Debug Mode

Enable verbose auth logging:

```yaml
logging:
  level: debug

auth:
  enabled: true
  # Auth decisions logged at debug level
```

### Testing Auth Locally

```bash
# Start with auth disabled
gibson daemon start --config configs/gibson.yaml

# Or with local tokens
cat > /tmp/auth-test.yaml <<EOF
auth:
  enabled: true
  local:
    users:
      - name: test
        token: test-token
        roles: ["admin"]
EOF

gibson daemon start --config /tmp/auth-test.yaml

# Test with token
grpcurl -H "authorization: Bearer test-token" \
  localhost:50051 gibson.DaemonService/GetStatus
```

## Performance

### Latency Impact

| Scenario | Added Latency |
|----------|---------------|
| Auth disabled | 0ms |
| Localhost bypass | <0.1ms |
| Cached JWKS + valid token | ~1-2ms |
| JWKS cache miss | ~50-200ms (HTTP fetch) |
| Token validation failure | ~1ms |

### Scaling Considerations

- JWKS cache is in-memory, shared across all requests
- Background refresh prevents cache-miss latency spikes
- Prometheus metrics add negligible overhead
- For high-throughput, consider increasing `jwks_ttl`

## Migration Guide

### From No Auth

1. Deploy with `auth.enabled: false` (default)
2. Configure OIDC providers in config
3. Test with `trust_localhost: true` locally
4. Enable auth: `auth.enabled: true`
5. Roll out to staging, then production

### From External Auth (oauth2-proxy, etc.)

1. Keep external auth in place
2. Add Gibson OIDC config pointing to same IdP
3. Enable Gibson auth
4. Remove external auth (Gibson handles it now)
5. Or: keep external + set `trust_localhost: true` to trust forwarded identity
