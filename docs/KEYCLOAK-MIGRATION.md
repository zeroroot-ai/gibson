# Migrating from Dex to Keycloak

This guide covers the migration from Dex to Keycloak as Gibson's identity provider. It is intended for operators upgrading an existing Gibson deployment that was previously using Dex for OIDC authentication.

## Table of Contents

- [Overview](#overview)
- [Breaking Changes](#breaking-changes)
- [Pre-Migration Checklist](#pre-migration-checklist)
- [Step-by-Step Migration](#step-by-step-migration)
- [Helm Values Changes](#helm-values-changes)
- [IdP Migration Matrix](#idp-migration-matrix)
- [Redis Membership Cleanup](#redis-membership-cleanup)
- [Rollback Procedure](#rollback-procedure)
- [FAQ](#faq)

---

## Overview

Gibson has replaced Dex with Keycloak as its identity provider. This change affects authentication for both the dashboard (OIDC login) and the daemon (JWT token validation).

**Why Keycloak?**

- **Full admin API** -- Keycloak exposes a comprehensive Admin REST API that Gibson uses to manage tenants, users, roles, and organizations programmatically. Dex had no admin API; all configuration was static YAML.
- **Organizations support** -- Keycloak's Organization feature (enabled via `KC_FEATURES=organization`) maps directly to Gibson's multi-tenant model. Each tenant becomes a Keycloak organization with its own membership and IdP federation.
- **MembershipTracker elimination** -- With Dex, Gibson maintained a custom `MembershipTracker` that stored team membership in Redis (`tenant:*:member:*` and `tenant:*:members` keys). This was a workaround for Dex's lack of user management. Keycloak handles all of this natively.
- **Identity provider federation** -- Keycloak supports LDAP user federation, SAML, OIDC, social logins, and more -- all configurable through its admin console or API. Dex connectors are replaced by Keycloak identity providers.
- **Realm-per-tenant isolation** -- In SaaS mode, each tenant can have its own Keycloak realm with isolated users, clients, and identity providers.

**What changed:**

| Component | Before (Dex) | After (Keycloak) |
|-----------|--------------|-------------------|
| Identity provider | Dex (static YAML config) | Keycloak (Admin API + console) |
| OIDC issuer URL | `https://<host>/dex` | `https://<host>/realms/gibson` |
| User/team management | Custom MembershipTracker (Redis) | Keycloak Admin API |
| IdP connectors | Dex connectors (YAML) | Keycloak identity providers (API/console) |
| Helm values prefix | `dex.*` | `keycloak.*` |
| Dashboard secret | `OIDC_CLIENT_SECRET` (manual) | Auto-generated, synced via realm-init Job |

---

## Breaking Changes

### 1. Dex removed entirely

All `dex.*` Helm values have been removed. Any custom Dex configuration (connectors, static clients, etc.) must be migrated to Keycloak equivalents. The Dex Deployment, Service, and ConfigMap are no longer rendered.

### 2. OIDC issuer URL format changed

```
# Before (Dex)
OIDC_ISSUER=https://auth.example.com/dex

# After (Keycloak)
OIDC_ISSUER=https://auth.example.com/realms/gibson
```

Any application or service that validates Gibson-issued tokens must be updated to use the new issuer URL. This includes:
- The dashboard (`dashboard.oidc.issuer`)
- The daemon OIDC provider config (`gibson.auth.oidc[].issuer`)
- Any external services that verify Gibson JWTs

### 3. New environment variables and Helm values

The following are now required when Keycloak is enabled:

| Variable | Source | Description |
|----------|--------|-------------|
| `KEYCLOAK_ADMIN` | `keycloak.auth.adminUser` | Keycloak admin username |
| `KEYCLOAK_ADMIN_PASSWORD` | Auto-generated Secret | Keycloak admin password |
| `KEYCLOAK_ADMIN_CLIENT_SECRET` | Auto-generated Secret | Service account client secret for Admin API |
| `KC_DB_PASSWORD` | Auto-generated Secret | Keycloak database password |

These are all managed automatically by the Helm chart. You do not need to set them manually unless you want to use specific values.

### 4. MembershipTracker removed

The `MembershipTracker` component that wrote team membership data to Redis has been deleted. If you were querying Redis keys matching `tenant:*:member:*` or `tenant:*:members` directly (outside of Gibson), those keys are now stale and will no longer be updated.

Team and user management is now handled through the Keycloak Admin API. The Gibson daemon communicates with Keycloak using a service account client (`gibson-admin`).

### 5. Dashboard OIDC must point to Keycloak realm URL

The dashboard's `OIDC_ISSUER` must be set to the Keycloak realm URL. When Keycloak is deployed in-cluster, the Helm chart also sets `OIDC_ISSUER_INTERNAL` automatically for cluster-internal token validation.

---

## Pre-Migration Checklist

Before starting the migration, complete the following:

### 1. Back up Redis data

```bash
# Port-forward to Redis
kubectl port-forward svc/<release>-redis-stack 6379:6379 -n <namespace>

# Dump all tenant membership keys for reference
redis-cli -h 127.0.0.1 -p 6379 -a <redis-password> --no-auth-warning \
  --scan --pattern "tenant:*:member:*" > membership-keys-backup.txt

redis-cli -h 127.0.0.1 -p 6379 -a <redis-password> --no-auth-warning \
  --scan --pattern "tenant:*:members" >> membership-keys-backup.txt

# Export key values
while read key; do
  echo "KEY: $key"
  redis-cli -h 127.0.0.1 -p 6379 -a <redis-password> --no-auth-warning GET "$key"
done < membership-keys-backup.txt > membership-data-backup.txt
```

### 2. Note current Dex connector configuration

Record your existing Dex connectors so you can recreate them in Keycloak. Check your current Helm values:

```bash
# Extract Dex config from your values file
helm get values <release> -n <namespace> | grep -A 50 "^dex:"
```

For each connector, note:
- Connector type (LDAP, SAML, OIDC, etc.)
- Connection parameters (host, port, bind DN, base DN for LDAP; metadata URL for SAML; etc.)
- Group/attribute mappings

### 3. Note current OIDC client configuration

```bash
# Check dashboard OIDC settings
helm get values <release> -n <namespace> | grep -A 10 "oidc:"
```

Record:
- Client ID
- Redirect URIs
- Scopes
- Any custom claims mappings

### 4. Plan Keycloak database

Keycloak requires a PostgreSQL database. You have two options:

| Option | Configuration | Use case |
|--------|--------------|----------|
| Shared PostgreSQL | Leave `keycloak.database.host` empty (default) | Development, small deployments |
| Dedicated PostgreSQL | Set `keycloak.database.host` to dedicated instance | Production, compliance requirements |

If using the shared PostgreSQL, the Helm chart creates a `keycloak` database automatically. If using a dedicated instance, create the database and user beforehand:

```sql
CREATE DATABASE keycloak;
CREATE USER keycloak WITH PASSWORD '<password>';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
```

### 5. Schedule a maintenance window

The migration involves switching the OIDC provider, which will invalidate existing user sessions. Users will need to re-authenticate after the switch. Plan for a brief authentication outage.

---

## Step-by-Step Migration

### Step 1: Deploy Keycloak alongside Dex (parallel run)

Enable Keycloak in your Helm values while keeping the existing Dex configuration. This deploys Keycloak without disrupting current authentication.

```yaml
# values-migration.yaml
keycloak:
  enabled: true
  image:
    repository: quay.io/keycloak/keycloak
    tag: "26.0"
  auth:
    adminUser: admin
  database:
    vendor: postgres
    host: ""          # Uses shared PostgreSQL
    port: 5432
    database: keycloak
    username: keycloak
  service:
    type: ClusterIP
    httpPort: 8080
  realmInit:
    enabled: true
    defaultRoles:
      - owner
      - admin
      - operator
      - viewer
```

Deploy:

```bash
helm upgrade <release> deploy/helm/gibson/ \
  -n <namespace> \
  -f your-values.yaml \
  -f values-migration.yaml
```

Verify Keycloak is running:

```bash
# Check pod status
kubectl get pods -n <namespace> -l app.kubernetes.io/component=keycloak

# Check realm-init job completed
kubectl get jobs -n <namespace> -l app.kubernetes.io/component=keycloak-realm-init

# Verify Keycloak health
kubectl exec -it <keycloak-pod> -n <namespace> -- \
  curl -sf http://localhost:8080/health/ready
```

### Step 2: Configure Keycloak realm and IdP federation

Access the Keycloak admin console:

```bash
# Port-forward to Keycloak
kubectl port-forward svc/<release>-keycloak 8080:8080 -n <namespace>

# Get admin password
kubectl get secret <release>-keycloak-secrets -n <namespace> \
  -o jsonpath='{.data.admin-password}' | base64 -d
```

Open `http://localhost:8080` and log in with the admin credentials. Then configure identity providers to match your existing Dex connectors (see [IdP Migration Matrix](#idp-migration-matrix) below).

For each Dex connector you had configured:

1. Navigate to the `gibson` realm
2. Go to **Identity Providers**
3. Add the equivalent Keycloak identity provider
4. Configure connection parameters from your pre-migration notes
5. Set up attribute/group mappers to match your existing claims

### Step 3: Test authentication against Keycloak

Before switching the dashboard, verify that Keycloak authentication works:

```bash
# Get the OIDC client secret
kubectl get secret <release>-dashboard-secret -n <namespace> \
  -o jsonpath='{.data.OIDC_CLIENT_SECRET}' | base64 -d

# Test token endpoint (resource owner password grant -- for testing only)
curl -X POST "http://localhost:8080/realms/gibson/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=gibson-dashboard" \
  -d "client_secret=<client-secret>" \
  -d "username=<test-user>" \
  -d "password=<test-password>"

# Verify the token contains expected claims
# Decode the access_token at jwt.io or with:
echo "<access_token>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Confirm the token contains:
- `iss` matching `http://<keycloak-host>/realms/gibson`
- `tenant_id` claim (added by the realm-init protocol mapper)
- Expected roles and group claims

### Step 4: Switch dashboard OIDC to Keycloak

Update your Helm values to point the dashboard at Keycloak:

```yaml
dashboard:
  oidc:
    enabled: true
    # For external access, use the public Keycloak URL
    issuer: "https://auth.example.com/realms/gibson"
    # For Kind/local dev:
    # issuer: "http://localhost:30080/realms/gibson"
    clientId: "gibson-dashboard"
    providerName: "Sign in with SSO"
```

If the daemon validates tokens, update its OIDC config too:

```yaml
gibson:
  auth:
    mode: "enterprise"  # or "saas"
    oidc:
      - issuer: "https://auth.example.com/realms/gibson"
        audience: "gibson-dashboard"
```

Deploy the update:

```bash
helm upgrade <release> deploy/helm/gibson/ \
  -n <namespace> \
  -f your-values.yaml
```

Verify the dashboard redirects to Keycloak for login:

```bash
# Check the dashboard pod picked up the new OIDC config
kubectl exec -it <dashboard-pod> -n <namespace> -- env | grep OIDC
```

### Step 5: Remove Dex from Helm values

Once Keycloak authentication is confirmed working, remove all `dex.*` values from your Helm values file. If Dex resources are still present in the cluster, delete them manually:

```bash
# Remove Dex resources (adjust names to match your release)
kubectl delete deployment <release>-dex -n <namespace> --ignore-not-found
kubectl delete service <release>-dex -n <namespace> --ignore-not-found
kubectl delete configmap <release>-dex -n <namespace> --ignore-not-found
kubectl delete secret <release>-dex -n <namespace> --ignore-not-found
```

### Step 6: Clean up stale Redis membership keys (optional)

The old MembershipTracker wrote keys to Redis that are no longer needed. Run the cleanup migration Job:

```yaml
keycloak:
  migration:
    cleanupRedis: true
```

```bash
helm upgrade <release> deploy/helm/gibson/ \
  -n <namespace> \
  -f your-values.yaml
```

The Job runs as a `post-upgrade` Helm hook and removes only:
- `tenant:*:member:*` -- individual member records
- `tenant:*:members` -- member set keys

It does **NOT** touch:
- `tenant:*:meta` -- tenant metadata / billing data
- Mission data, tool queues, or any other Redis keys

Monitor the Job:

```bash
# Watch the job
kubectl get jobs -n <namespace> -l app.kubernetes.io/component=keycloak-migration

# Check logs
kubectl logs -n <namespace> -l app.kubernetes.io/component=keycloak-migration
```

After the Job completes, set `cleanupRedis` back to `false` to prevent it from running on subsequent upgrades:

```yaml
keycloak:
  migration:
    cleanupRedis: false
```

---

## Helm Values Changes

### Before (Dex)

```yaml
# OLD: Dex configuration (no longer supported)
dex:
  enabled: true
  image:
    repository: ghcr.io/dexidp/dex
    tag: "v2.38.0"
  config:
    issuer: "https://auth.example.com/dex"
    connectors:
      - type: ldap
        name: "Corporate LDAP"
        config:
          host: ldap.corp.example.com:636
          bindDN: "cn=service,dc=example,dc=com"
          bindPW: "${LDAP_BIND_PASSWORD}"
          userSearch:
            baseDN: "ou=users,dc=example,dc=com"
            filter: "(objectClass=person)"
            username: sAMAccountName
          groupSearch:
            baseDN: "ou=groups,dc=example,dc=com"
            filter: "(objectClass=group)"
    staticClients:
      - id: gibson-dashboard
        name: "Gibson Dashboard"
        redirectURIs:
          - "https://dashboard.example.com/api/auth/callback/oidc"
        secret: "${OIDC_CLIENT_SECRET}"
  service:
    type: ClusterIP
    port: 5556

dashboard:
  oidc:
    enabled: true
    issuer: "https://auth.example.com/dex"
    clientId: "gibson-dashboard"
```

### After (Keycloak)

```yaml
# NEW: Keycloak configuration
keycloak:
  enabled: true
  image:
    repository: quay.io/keycloak/keycloak
    tag: "26.0"
  auth:
    adminUser: admin
    # adminPassword auto-generated, stored in Secret
  database:
    vendor: postgres
    host: ""        # Uses shared PostgreSQL
    port: 5432
    database: keycloak
    username: keycloak
  service:
    type: ClusterIP
    httpPort: 8080
  extraEnvVars:
    KC_FEATURES: "organization"
    KC_HEALTH_ENABLED: "true"
    KC_METRICS_ENABLED: "true"
  realmInit:
    enabled: true
    defaultRoles:
      - owner
      - admin
      - operator
      - viewer
  migration:
    cleanupRedis: false   # Set true on first upgrade from Dex

# LDAP is now configured in Keycloak admin console or via Admin API
# (see IdP Migration Matrix below)

dashboard:
  oidc:
    enabled: true
    issuer: "https://auth.example.com/realms/gibson"   # <-- note /realms/gibson
    clientId: "gibson-dashboard"
    # clientSecret auto-generated, synced to Keycloak by realm-init Job
```

### Key differences

| Setting | Dex | Keycloak |
|---------|-----|----------|
| Enabled flag | `dex.enabled` | `keycloak.enabled` |
| Image | `ghcr.io/dexidp/dex:v2.38.0` | `quay.io/keycloak/keycloak:26.0` |
| Issuer URL path | `/dex` | `/realms/gibson` |
| IdP connectors | `dex.config.connectors[]` (YAML) | Keycloak admin console / Admin API |
| Static clients | `dex.config.staticClients[]` (YAML) | Realm-init Job creates `gibson-dashboard` client |
| Client secret | Manual in values | Auto-generated, preserved on upgrade |
| User management | MembershipTracker (Redis) | Keycloak Admin API |
| Service port | `5556` | `8080` |

---

## IdP Migration Matrix

Use this table to find the Keycloak equivalent for each Dex connector you had configured:

| Dex Connector | Keycloak Equivalent | Configuration Path |
|--------------|---------------------|-------------------|
| **LDAP** | User Federation > LDAP Provider | Realm Settings > User Federation > Add LDAP provider |
| **SAML** | Identity Providers > SAML | Identity Providers > Add provider > SAML v2.0 |
| **OIDC (generic)** | Identity Providers > OpenID Connect | Identity Providers > Add provider > OpenID Connect v1.0 |
| **OIDC (Okta)** | Identity Providers > OpenID Connect | Identity Providers > Add provider > OpenID Connect v1.0 (use Okta issuer URL) |
| **Microsoft** | Identity Providers > Microsoft | Identity Providers > Add provider > Microsoft |
| **Google** | Identity Providers > Google | Identity Providers > Add provider > Google |
| **GitHub** | Identity Providers > GitHub | Identity Providers > Add provider > GitHub |
| **GitLab** | Identity Providers > OpenID Connect | Identity Providers > Add provider > OpenID Connect v1.0 (use GitLab issuer URL) |
| **Bitbucket** | Identity Providers > Bitbucket | Identity Providers > Add provider > Bitbucket |
| **Static Passwords** | Keycloak local users | Manage > Users > Add user (set password in Credentials tab) |

### LDAP migration notes

Dex LDAP connectors map to Keycloak LDAP User Federation. Key field mappings:

| Dex field | Keycloak field |
|-----------|---------------|
| `config.host` | Connection URL (`ldaps://host:636`) |
| `config.bindDN` | Bind DN |
| `config.bindPW` | Bind Credential |
| `config.userSearch.baseDN` | Users DN |
| `config.userSearch.filter` | Custom User LDAP Filter |
| `config.userSearch.username` | Username LDAP attribute |
| `config.groupSearch.baseDN` | Group LDAP DN (under LDAP mappers) |
| `config.groupSearch.filter` | Group LDAP Filter (under LDAP mappers) |

### SAML migration notes

Dex SAML connectors map to Keycloak SAML Identity Providers:

1. In the `gibson` realm, go to **Identity Providers > Add provider > SAML v2.0**
2. Enter the SAML metadata URL or upload the metadata XML
3. Configure attribute mappers to map SAML assertions to Keycloak user attributes
4. If you need group claims in tokens, add a Group Membership mapper to the `gibson-dashboard` client

### Social login migration notes

For GitHub, Google, and Microsoft connectors, Keycloak has built-in social providers. You will need the OAuth client ID and secret from the respective provider's developer console. These are the same credentials you used in your Dex connector configuration.

---

## Redis Membership Cleanup

### What gets cleaned up

The migration Job targets Redis keys that were written by the now-removed `MembershipTracker`:

| Key pattern | Description | Action |
|-------------|-------------|--------|
| `tenant:*:member:*` | Individual member records (user-to-tenant mapping) | **Deleted** |
| `tenant:*:members` | Sets of member IDs per tenant | **Deleted** |
| `tenant:*:meta` | Tenant metadata (billing, plan, settings) | **Not touched** |
| `mission:*` | Mission execution data | **Not touched** |
| `tool:*` / `queue:*` | Tool job queues and results | **Not touched** |

### Running the cleanup manually

If you prefer to run the cleanup manually instead of using the Helm hook:

```bash
# Port-forward to Redis
kubectl port-forward svc/<release>-redis-stack 6379:6379 -n <namespace>

# Preview what would be deleted (dry run)
redis-cli -h 127.0.0.1 -p 6379 -a <redis-password> --no-auth-warning \
  --scan --pattern "tenant:*:member:*"

redis-cli -h 127.0.0.1 -p 6379 -a <redis-password> --no-auth-warning \
  --scan --pattern "tenant:*:members"

# Delete member record keys
redis-cli -h 127.0.0.1 -p 6379 -a <redis-password> --no-auth-warning \
  --scan --pattern "tenant:*:member:*" | xargs -r redis-cli -h 127.0.0.1 \
  -p 6379 -a <redis-password> --no-auth-warning DEL

# Delete member set keys
redis-cli -h 127.0.0.1 -p 6379 -a <redis-password> --no-auth-warning \
  --scan --pattern "tenant:*:members" | xargs -r redis-cli -h 127.0.0.1 \
  -p 6379 -a <redis-password> --no-auth-warning DEL
```

---

## Rollback Procedure

If you need to revert to Dex after switching to Keycloak:

### 1. Re-enable Dex in Helm values

Restore your original `dex.*` values and redeploy:

```bash
helm upgrade <release> deploy/helm/gibson/ \
  -n <namespace> \
  -f your-original-values.yaml
```

### 2. Point dashboard back to Dex issuer

```yaml
dashboard:
  oidc:
    issuer: "https://auth.example.com/dex"
```

### 3. Point daemon back to Dex issuer

```yaml
gibson:
  auth:
    oidc:
      - issuer: "https://auth.example.com/dex"
```

### 4. Disable Keycloak

```yaml
keycloak:
  enabled: false
```

### 5. Redeploy

```bash
helm upgrade <release> deploy/helm/gibson/ \
  -n <namespace> \
  -f your-values.yaml
```

### 6. Clean up Keycloak resources

```bash
kubectl delete statefulset <release>-keycloak -n <namespace> --ignore-not-found
kubectl delete service <release>-keycloak -n <namespace> --ignore-not-found
kubectl delete service <release>-keycloak-headless -n <namespace> --ignore-not-found
kubectl delete configmap <release>-keycloak-config -n <namespace> --ignore-not-found
kubectl delete secret <release>-keycloak-secrets -n <namespace> --ignore-not-found
kubectl delete job <release>-keycloak-realm-init -n <namespace> --ignore-not-found
```

Note: The Redis membership keys that were deleted by the migration Job cannot be restored automatically. If you backed up the data in the pre-migration step, you can restore it manually. However, since Dex will resume writing fresh membership data, this is typically unnecessary.

---

## FAQ

### Q: Do I need to run the Redis cleanup?

No. The stale membership keys are harmless -- they just consume a small amount of memory. The cleanup is optional and provided for hygiene. Run it if you want a clean Redis state, skip it if you prefer to leave things alone.

### Q: Will existing user sessions survive the migration?

No. Switching the OIDC issuer invalidates all existing sessions because the tokens were issued by Dex and cannot be validated against Keycloak. Users will need to log in again after the switch. Plan for a brief authentication outage.

### Q: Can I run Dex and Keycloak simultaneously?

Yes, during the migration (Steps 1-3). Both can be deployed at the same time. The dashboard will use whichever issuer is configured in `dashboard.oidc.issuer`. The daemon can also accept tokens from multiple issuers if you configure multiple entries in `gibson.auth.oidc[]`.

### Q: What happens to my LDAP users?

LDAP users are not stored in Dex -- they are authenticated on each login by querying the LDAP server. When you configure the same LDAP server as a Keycloak User Federation provider, users will be able to log in with the same credentials. Keycloak will import user records into its database on first login (configurable).

### Q: Do I need to recreate all my users in Keycloak?

Only if you were using Dex static passwords. LDAP, SAML, and OIDC-federated users will authenticate through the same external IdP -- you just need to configure the equivalent Keycloak identity provider or user federation. For static password users, create them as local Keycloak users in the `gibson` realm.

### Q: What about the `tenant:*:meta` keys in Redis?

These are tenant metadata keys (billing, plan information, settings) that are managed by a separate component. The migration Job explicitly does not touch them. They remain valid and operational.

### Q: Can I use an external Keycloak instance instead of the Helm-deployed one?

Yes. Set `keycloak.enabled: false` and configure the dashboard and daemon to point to your external Keycloak instance:

```yaml
keycloak:
  enabled: false

dashboard:
  oidc:
    issuer: "https://your-keycloak.example.com/realms/gibson"
    clientId: "gibson-dashboard"
    clientSecret: "<your-client-secret>"

gibson:
  auth:
    mode: "enterprise"
    oidc:
      - issuer: "https://your-keycloak.example.com/realms/gibson"
        audience: "gibson-dashboard"
```

You will need to manually create the `gibson` realm, the `gibson-dashboard` client, and the required roles and protocol mappers in your external Keycloak instance. The realm-init Job can serve as a reference for what needs to be configured.

### Q: The realm-init Job failed. What do I do?

Check the Job logs:

```bash
kubectl logs -n <namespace> -l app.kubernetes.io/component=keycloak-realm-init
```

Common issues:
- **Keycloak not ready** -- The init container waits for Keycloak health, but if it times out, check that the Keycloak pod is running and healthy.
- **Database connection failed** -- Verify that the PostgreSQL database exists and the credentials are correct.
- **Realm already exists** -- This is safe. The Job uses `|| echo "... may already exist"` for idempotency.

The Job has `backoffLimit: 5` and runs on both `post-install` and `post-upgrade`, so it will retry automatically.

### Q: How do I add the `tenant_id` claim to tokens for an external IdP?

The realm-init Job creates a hardcoded claim mapper that sets `tenant_id` to `"gibson"` for single-tenant deployments. For multi-tenant setups with external IdPs, you have two options:

1. **IdP mapper** -- Configure an attribute mapper in the Keycloak identity provider to extract the tenant ID from the external IdP's token and map it to a user attribute, then add a User Attribute protocol mapper to include it in the `gibson-dashboard` client's tokens.

2. **Organization mapper** -- If using Keycloak Organizations (enabled by default with `KC_FEATURES=organization`), add users to organizations and use an Organization Membership protocol mapper to populate the `tenant_id` claim.
