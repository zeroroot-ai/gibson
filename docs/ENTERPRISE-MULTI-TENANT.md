# Enterprise Multi-Tenant Setup Guide

## Overview

Gibson enterprise mode supports single-tenant and multi-tenant deployments sharing the same Helm chart. The difference is entirely in how a user's workspace is determined at login time.

| Mode | How tenant is resolved | Use case |
|------|----------------------|----------|
| **Single-tenant** | `defaultTenant` config value | One security team, one company |
| **Multi-tenant** | Value of a JWT claim from the IdP | Multiple teams/departments sharing one Gibson instance |

Both modes use the same OIDC/Keycloak authentication path — the only change is which config key drives tenant resolution.

## Architecture: How Tenant Isolation Works

```
User logs in via corporate IdP
  → Keycloak issues OIDC token
    → "department" claim = "appsec"
      → Gibson extracts claim value → tenant = "appsec"
        → All missions, findings, scope, memory namespaced under "appsec"
          → User from "devsecops" cannot see "appsec" data
```

Tenant namespacing is enforced at the storage layer:

- **Redis** keys are prefixed: `mission:{tenant}:*`, `plugin-access:{tenant}:*`
- **Neo4j** nodes carry a `tenant` property — all queries are scoped
- **Findings** include tenant metadata, queries filter by it

There is no tenant-level network isolation — all tenants share the same pod infrastructure.

## Quick Start: Enabling Multi-Tenancy

### Step 1: Choose your tenant claim

Your IdP must emit a JWT claim whose value identifies the user's team. Pick one claim and use it consistently.

| IdP | Recommended claim | Source of the value |
|-----|------------------|-------------------|
| LDAP / Active Directory | `department` | LDAP `department` attribute on the user entry |
| Okta | `groups` or a custom attribute | Okta Groups or Profile attribute |
| Azure AD / Entra ID | `department` or `groups` | AD attribute or group membership |
| SAML | `groups` | SAML assertion attribute configured in the IdP |
| Google Workspace | `groups` | Directory Groups (requires service account) |

If your IdP emits a `groups` list and you want the first group to be the tenant, you can configure a Keycloak protocol mapper with a custom claim name or use a JavaScript mapper to transform the value. If the claim value is a single string (like `department`), it maps directly via a standard User Attribute mapper.

### Step 2: Update Helm values

Change from single-tenant:

```yaml
gibson:
  auth:
    mode: "enterprise"
    defaultTenant: "my-company"
```

To multi-tenant:

```yaml
gibson:
  auth:
    mode: "enterprise"
    tenantClaim: "department"      # must match the claim name in your JWT
    autoProvisionTenants: true     # auto-create workspace on first login
    # defaultTenant: "my-company" # remove or comment out
```

Both keys can coexist: `defaultTenant` acts as a fallback when a user's token is missing the `tenantClaim` value.

### Step 3: Configure Keycloak to pass the claim

The claim must reach Gibson inside the Keycloak-issued OIDC token. You configure this using **protocol mappers** in the Keycloak admin console or via realm import JSON.

**Using the Keycloak Admin Console (http://{host}:8080/admin):**

1. Navigate to your realm, then **Clients** > select the `gibson` client > **Client scopes** tab > click the dedicated scope (e.g., `gibson-dedicated`).
2. Click **Add mapper** > **By configuration** > choose the appropriate mapper type.

**LDAP — pass `department` attribute:**

If Keycloak is federated with LDAP, the `department` attribute is automatically synced to the user profile. Create a **User Attribute** protocol mapper to include it in the token:

1. In the client scope, click **Add mapper** > **By configuration** > **User Attribute**.
2. Configure:
   - Name: `department`
   - User Attribute: `department`
   - Token Claim Name: `department`
   - Claim JSON Type: `String`
   - Add to ID token: **ON**
   - Add to access token: **ON**

If your LDAP only reliably provides group membership, use `tenantClaim: "groups"` instead and map group names to your team names using Keycloak's **Group Membership** mapper.

**Okta — federated via OIDC Identity Provider:**

If Keycloak federates to Okta as an external OIDC identity provider:

1. In the Keycloak admin console, go to **Identity Providers** > select your Okta provider > **Mappers** tab.
2. Add an **Attribute Importer** mapper to import `department` from the Okta token into the Keycloak user profile.
3. Then add a **User Attribute** protocol mapper on the `gibson` client scope (as described above) to include `department` in the Gibson-bound token.

Then set `tenantClaim: "department"` in Gibson.

**Azure AD — federated via OIDC or SAML:**

If Keycloak federates to Azure AD:

1. In the Azure app registration, ensure `department` is included as an optional claim.
2. In Keycloak, add an **Attribute Importer** mapper on the Azure AD identity provider to sync `department` to the user profile.
3. Add a **User Attribute** protocol mapper on the `gibson` client scope to emit `department` in the token.

Alternatively use `groups` if your AD is already structured by security group. Keycloak's **Group Membership** mapper can emit groups from the Keycloak-side group model.

**SAML — federated via SAML Identity Provider:**

If Keycloak federates to a SAML IdP:

1. Ensure the SAML IdP includes the `department` attribute in the assertion:

```xml
<saml:Attribute Name="department">
  <saml:AttributeValue>appsec</saml:AttributeValue>
</saml:Attribute>
```

2. In Keycloak, go to **Identity Providers** > select your SAML provider > **Mappers** tab.
3. Add an **Attribute Importer** mapper:
   - Mapper Type: `Attribute Importer`
   - Attribute Name: `department`
   - User Attribute Name: `department`
4. Add a **User Attribute** protocol mapper on the `gibson` client scope to emit `department` in the OIDC token.

**Realm Import JSON (GitOps-friendly):**

Instead of configuring mappers via the admin console, you can define them in a realm import JSON file:

```json
{
  "clients": [
    {
      "clientId": "gibson",
      "protocolMappers": [
        {
          "name": "department",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-attribute-mapper",
          "config": {
            "user.attribute": "department",
            "claim.name": "department",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true"
          }
        },
        {
          "name": "group-membership",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "config": {
            "claim.name": "groups",
            "full.path": "false",
            "id.token.claim": "true",
            "access.token.claim": "true"
          }
        }
      ]
    }
  ]
}
```

Apply this via the Keycloak CLI or include it in your Helm deployment (see Step 4).

### Step 4: Deploy

```bash
helm upgrade --install gibson deploy/helm/gibson/ \
  -f deploy/helm/gibson/values-enterprise.yaml \
  --set keycloak.auth.adminPassword="$KEYCLOAK_ADMIN_PASSWORD"
```

If Keycloak federates to an external IdP that requires client credentials, create a Kubernetes Secret and reference it in Keycloak's identity provider configuration:

```bash
# Create a secret for external IdP client credentials
kubectl create secret generic keycloak-idp-secret \
  --from-literal=clientSecret="$IDP_CLIENT_SECRET" \
  -n gibson

# For LDAP federation, pass the bind password
kubectl create secret generic keycloak-ldap-secret \
  --from-literal=bindCredential="$LDAP_BIND_PASSWORD" \
  -n gibson
```

These secrets are referenced in the Keycloak realm configuration (admin console or realm import JSON), not passed as Helm `--set` flags. Keycloak manages its own identity provider and user federation configuration internally.

### Step 5: Verify isolation

1. Log in as a user whose IdP claim resolves to `team-a`.
2. Create a mission and note its ID.
3. Log out and log in as a user whose IdP claim resolves to `team-b`.
4. Confirm the mission created in step 2 does not appear in the mission list.
5. Confirm the Gibson daemon logs show `tenant=team-b` for the second session.

## Role Bindings by Group

Role bindings are configured per OIDC provider in `values-enterprise.yaml`. They map IdP group names to Gibson permission roles and support glob patterns.

```yaml
gibson:
  auth:
    oidc:
      - issuer: "http://gibson-keycloak:8080/realms/gibson"
        audience: "gibson"
        roleBindings:
          "security-admins":
            - "admin"
          "security-operators":
            - "mission:execute"
            - "mission:read"
            - "findings:read"
          "security-*":           # glob: matches security-team, security-eng, etc.
            - "findings:read"
          "developers":
            - "findings:read"
```

A user's effective roles are the union of all matching bindings. Role matching is evaluated against the `groups` claim from the OIDC token.

## Switching Between Modes

### Single-tenant to multi-tenant

Follow Steps 1-4 above. Existing data created under `defaultTenant` is preserved under that tenant namespace in Redis and Neo4j. Users whose new claim value matches the old `defaultTenant` value will see existing data automatically. Users with different claim values start with an empty workspace.

### Multi-tenant to single-tenant (rollback)

```yaml
gibson:
  auth:
    mode: "enterprise"
    defaultTenant: "my-company"
    # tenantClaim: ""  # Remove or comment out
```

```bash
helm upgrade gibson deploy/helm/gibson/ \
  -f deploy/helm/gibson/values-enterprise.yaml
```

All users will now resolve to `my-company` regardless of their JWT claims. Data stored under other tenant prefixes in Redis and Neo4j is not deleted — it is simply unreachable until `tenantClaim` is restored.

## Managing Tenants via Admin API

When `autoProvisionTenants: false`, tenants must be created before users from that department can log in.

```bash
# Create a tenant
gibson tenant create --name "appsec" --display-name "Application Security"

# List tenants
gibson tenant list

# Disable a tenant (blocks login, preserves data)
gibson tenant disable --name "appsec"
```

The admin API requires the `admin` role. Service account tokens with `admin` scope can also call these endpoints programmatically.

## Production Checklist

- [ ] `trustLocalhost: false` is set (default in `values-enterprise.yaml`)
- [ ] `disableAuth: false` on the dashboard (default)
- [ ] LDAP `bindPW` is injected at deploy time via `--set` or an external secret — not committed to values files
- [ ] TLS is enabled on the LDAP connector (`rootCAData` set, or `startTLS: true`)
- [ ] Keycloak realm `gibson` has valid redirect URIs configured for the dashboard's external hostname
- [ ] `autoProvisionTenants: false` if you want controlled onboarding
- [ ] `gibson.replicas: 2` and `keycloak.replicas: 2` for HA
- [ ] PVC sizes set before first install (resizing requires manual PV work)
- [ ] `prometheus.retention` set to your compliance requirement (default `30d` in enterprise overlay)

## FAQ

**Q: What happens to existing data when switching from single-tenant to multi-tenant?**

Data stored under the previous `defaultTenant` value stays accessible to users whose new claim value matches that string. New users with different claim values receive empty workspaces.

**Q: What if a user's token does not contain the tenantClaim?**

If `defaultTenant` is also set, the user falls back to that workspace. If neither condition is met, the request fails with `codes.Unauthenticated` and a message like `"tenant claim 'department' not present in token"`. This surfaces in the dashboard as a login error with a descriptive message.

**Q: Can a user belong to multiple tenants?**

The `tenantClaim` resolves one primary tenant per session. If a user needs access to a second tenant, an API key scoped to that tenant can be issued via the dashboard and used by scripts or CI pipelines. The dashboard does not currently support within-session tenant switching.

**Q: Does the system tenant `_system` appear in the tenant list?**

No. `_system` is a reserved namespace for platform-level plugins deployed by operators. It is not visible to end users and cannot be created or modified through the tenant admin API.

**Q: How do I debug token claim issues?**

Enable debug logging on the Gibson daemon temporarily:

```yaml
gibson:
  config:
    logging:
      level: debug
```

The auth interceptor logs the full decoded claim set (at `debug` level) when a request arrives, including which claim was selected as the tenant.

**Q: Can I use multiple IdP connectors simultaneously?**

Yes. Keycloak supports multiple identity providers (LDAP, SAML, OIDC) simultaneously within a single realm. Add identity providers via the Keycloak admin console (**Identity Providers** section) or via realm import JSON. Users are routed to the correct provider based on their selection on the Keycloak login page, or you can configure identity provider redirectors for automatic routing based on email domain. All federated identity providers must populate the same user attribute used by the protocol mapper that emits `tenantClaim` for consistent tenant resolution.
