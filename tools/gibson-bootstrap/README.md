# gibson-bootstrap

Single-purpose CLI invoked by the chart's `bootstrap-secrets` pre-install/pre-upgrade Job to provision Zitadel resources idempotently. Output is always a single compact JSON line on stdout; all log output goes to stderr.

## Subcommands

```
# Ensure a Zitadel organisation exists; create if absent.
ZITADEL_ISSUER=http://gibson-zitadel.gibson.svc.cluster.local:8080 \
ZITADEL_ADMIN_PAT=<pat> \
  gibson-bootstrap zitadel-ensure-org <name>
# stdout: {"org_id":"<id>","created":true|false}

# Mint (or retrieve) a confidential OIDC client within an existing project.
ZITADEL_ISSUER=http://gibson-zitadel.gibson.svc.cluster.local:8080 \
ZITADEL_ADMIN_PAT=<pat> \
ZITADEL_ORG_ID=<org-id> \
ZITADEL_PROJECT_ID=<project-id> \
  gibson-bootstrap zitadel-mint-oidc-client <client-name> [--rotate-secret]
# stdout: {"client_id":"<id>","client_secret":"<secret>","rotated":true|false}
```
