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
│        │ Login       │ OIDC JWT    │ SA Token          │ OIDC JWT     │
│        ▼             │             │                    │              │
│   ┌──────────────┐   │             │                    │              │
│   │  Keycloak    │   │             │                    │              │
│   │  :8080/      │   │             │                    │              │
│   │  realms/     │   │             │                    │              │
│   │  gibson      │   │             │                    │              │
│   │              │   │             │                    │              │
│   │ (LDAP/SAML/  │   │             │                    │              │
│   │  OIDC        │   │             │                    │              │
│   │  federation) │   │             │                    │              │
│   └──────┬───────┘   │             │                    │              │
│          │ OIDC JWT   │             │                    │              │
│          └────────────┴─────────────┴────────────────────┘              │
│                                    │                                    │
│                                    ▼                                    │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                      GIBSON DAEMON                              │   │
│   │  ┌──────────────────────────────────────────────────────────┐  │   │
│   │  │                 gRPC Auth Interceptor                     │  │   │
│   │  │                                                           │  │   │
│   │  │  1. Extract Bearer token from metadata                    │  │   │
│   │  │  2. Route to appropriate validator (OIDC/K8s/Local)       │  │   │
│   │  │  3. Validate signature via Keycloak JWKS endpoint         │  │   │
│   │  │     (.../realms/gibson/protocol/openid-connect/certs)     │  │   │
│   │  │  4. Validate expiry, issuer, audience                     │  │   │
│   │  │  5. Extract claims → map to Identity                      │  │   │
│   │  │  6. Resolve roles from bindings                           │  │   │
│   │  │  7. Inject Identity into request context                  │  │   │
│   │  │  8. RPCAuthzInterceptor enforces permissions.yaml         │  │   │
│   │  └──────────────────────────────────────────────────────────┘  │   │
│   │                              │                                  │   │
│   │                              ▼                                  │   │
│   │  ┌──────────────────────────────────────────────────────────┐  │   │
│   │  │              Mission / Agent / Finding Handlers           │  │   │
│   │  │                                                           │  │   │
│   │  │  // In handler — interceptor has already authorized:      │  │   │
│   │  │  identity, _ := auth.IdentityFromContext(ctx)             │  │   │
│   │  │  // use identity.Roles / identity.Subject for tenant      │  │   │
│   │  │  // data filtering only — no inline permission checks.    │  │   │
│   │  │                                                           │  │   │
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

**Key insight**: External clients authenticate via Keycloak (or other OIDC providers like GitHub Actions, GitLab CI). Keycloak handles user login, identity federation (LDAP, SAML, external OIDC), and token issuance. Gibson validates the resulting JWT tokens via the Keycloak JWKS endpoint. Internal agent-to-daemon communication uses NetworkPolicy (and optionally mTLS via service mesh) with zero auth overhead.

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

### Production Configuration (Keycloak)

```yaml
auth:
  enabled: true
  clock_skew: 30s        # Token expiry tolerance
  trust_localhost: false # Never in production

  oidc:
    # Keycloak — bundled enterprise IdP
    - issuer: "http://gibson-keycloak:8080/realms/gibson"
      audience: "gibson"
      jwks_ttl: 1h
      claims_mapping:
        groups: groups
        email: email
      role_bindings:
        "security-admins": ["admin"]
        "security-team": ["mission:execute", "findings:*"]
        "developers": ["findings:read"]
```

### Production Configuration (External IdP, e.g., Okta)

```yaml
auth:
  enabled: true
  clock_skew: 30s
  trust_localhost: false

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
    # Keycloak — bundled enterprise IdP
    - issuer: "http://gibson-keycloak:8080/realms/gibson"
      audience: "gibson"
      jwks_endpoint: ""           # Auto-discovered from issuer
      jwks_ttl: 1h                # How long to cache JWKS

      # Map token claims to identity fields
      # Keycloak emits groups via Group Membership mapper,
      # roles via realm_access.roles, email as a standard claim
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

    # External IdP (e.g., Okta — if not using Keycloak federation)
    # - issuer: https://company.okta.com
    #   audience: gibson-prod
    #   jwks_ttl: 1h
    #   claims_mapping:
    #     groups: groups
    #     email: email
    #   role_bindings:
    #     "security-admins": ["admin"]

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

### Keycloak Token Claim Structure

Keycloak tokens contain a specific claim structure that differs from other OIDC providers. Understanding this structure is important for configuring `claims_mapping` and `role_bindings` correctly.

**Standard Keycloak ID token claims:**

```json
{
  "iss": "http://gibson-keycloak:8080/realms/gibson",
  "sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "aud": "gibson",
  "exp": 1711900000,
  "iat": 1711896400,
  "email": "user@company.com",
  "email_verified": true,
  "preferred_username": "jdoe",
  "given_name": "Jane",
  "family_name": "Doe",
  "groups": [
    "security-admins",
    "appsec-team"
  ],
  "realm_access": {
    "roles": [
      "default-roles-gibson",
      "gibson-admin"
    ]
  },
  "resource_access": {
    "gibson": {
      "roles": [
        "mission-operator"
      ]
    }
  },
  "department": "appsec"
}
```

**Key claim locations:**

| Claim | Location | Source in Keycloak | Protocol Mapper Type |
|-------|----------|-------------------|---------------------|
| `groups` | Top-level array | Keycloak group membership | Group Membership mapper |
| `email` | Top-level string | User profile | Built-in |
| `realm_access.roles` | Nested object | Realm roles assigned to user | Built-in (realm roles) |
| `resource_access.gibson.roles` | Nested object | Client roles assigned to user | Built-in (client roles) |
| `department` | Top-level string | User attribute | User Attribute mapper |

**JWKS Endpoint:**

Keycloak serves JWKS keys at a realm-specific URL:

```
http://gibson-keycloak:8080/realms/gibson/protocol/openid-connect/certs
```

This is auto-discovered by Gibson from the issuer URL's `.well-known/openid-configuration` endpoint. You do not need to set `jwks_endpoint` explicitly unless your network topology requires a different URL for JWKS retrieval than the issuer URL.

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
# Start with dev mode (local static tokens)
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

### From Dex to Keycloak

If you are migrating from a previous Gibson deployment that used Dex as the OIDC provider:

1. **Deploy Keycloak alongside Dex** (both running temporarily):
   ```bash
   helm upgrade gibson deploy/helm/gibson/ \
     -f deploy/helm/gibson/values-enterprise.yaml \
     --set keycloak.enabled=true
   ```

2. **Recreate your identity provider configuration in Keycloak:**
   - Dex LDAP connectors become Keycloak **User Federation** > **LDAP** providers
   - Dex OIDC connectors (Okta, Azure AD, Google) become Keycloak **Identity Providers** > **OpenID Connect v1.0**
   - Dex SAML connectors become Keycloak **Identity Providers** > **SAML v2.0**

3. **Recreate claim mappings as Keycloak protocol mappers:**
   - Dex `groupSearch` / `groupsAttr` becomes a **Group Membership** protocol mapper on the `gibson` client scope
   - Dex `userSearch` attribute mappings become **User Attribute** protocol mappers
   - Custom Dex claim transformers become **Script Mapper** (JavaScript) protocol mappers

4. **Update the Gibson OIDC issuer configuration:**
   ```yaml
   # Before (Dex)
   auth:
     oidc:
       - issuer: "http://gibson-dex:5556/dex"
         audience: "gibson"

   # After (Keycloak)
   auth:
     oidc:
       - issuer: "http://gibson-keycloak:8080/realms/gibson"
         audience: "gibson"
   ```

5. **Test authentication with Keycloak:**
   ```bash
   # Get a token from Keycloak
   TOKEN=$(curl -s -X POST \
     "http://localhost:30080/realms/gibson/protocol/openid-connect/token" \
     -d "client_id=gibson" \
     -d "username=testuser" \
     -d "password=testpass" \
     -d "grant_type=password" | jq -r .access_token)

   # Verify Gibson accepts it
   grpcurl -H "authorization: Bearer $TOKEN" \
     localhost:30002 gibson.DaemonService/Ping
   ```

6. **Remove Dex from the deployment:**
   ```bash
   helm upgrade gibson deploy/helm/gibson/ \
     -f deploy/helm/gibson/values-enterprise.yaml \
     --set keycloak.enabled=true
   ```

**Key differences from Dex:**

| Aspect | Dex | Keycloak |
|--------|-----|----------|
| Configuration method | YAML connector blocks in Helm values | Admin console UI or realm import JSON |
| IdP federation | Static YAML connectors | Dynamic identity providers with auto-discovery |
| Claim customization | Limited (groups, email) | Full protocol mapper framework (User Attribute, Group Membership, Script, Hardcoded, etc.) |
| User management | Delegated entirely to upstream IdP | Built-in user management + federation |
| Admin UI | None | Full admin console at `:8080/admin` |
| Issuer URL pattern | `http://host:5556/dex` | `http://host:8080/realms/{realm}` |
| JWKS URL pattern | `http://host:5556/dex/keys` | `http://host:8080/realms/{realm}/protocol/openid-connect/certs` |
| Session management | Stateless | Server-side sessions with configurable lifetime |
| Multi-realm | N/A | Supports multiple realms for environment isolation |
