# Security policy

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through GitHub Security Advisories:
[Report a vulnerability](https://github.com/zeroroot-ai/gibson/security/advisories/new)

That opens a private thread visible only to maintainers, and gives us a place
to coordinate a fix and a CVE if one is warranted.

## What to expect

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or mitigation plan | communicated with the assessment |

If you have not heard back within 3 working days, assume the report did not
reach us and escalate through any other channel you have. Silence is a failure
on our side, not a decision.

## Scope

This repository is the platform: the daemon, the ext-authz service, the three
operators and the SPIFFE/JWKS sidecar. Findings in these are in scope,
particularly anything that crosses a tenant boundary.

**Cross-tenant issues are the highest severity we recognise.** World, timeline,
reducer and knowledge graph are per-tenant by design and fully isolated. Any
path where structure, event, projection or query spans tenants is a critical
finding regardless of how difficult it is to reach.

Other repositories have their own policies:
[`setec`](https://github.com/zeroroot-ai/setec) (the sandbox boundary),
[`charts`](https://github.com/zeroroot-ai/charts) (the install),
[`dashboard`](https://github.com/zeroroot-ai/dashboard) (the console).

## Out of scope

- Findings in a **deployment you control** that come from your own configuration — an over-broad grant you issued, a credential you committed, a network policy you disabled
- Anything requiring a privileged position we already assume hostile, such as cluster-admin on the host cluster
- Automated scanner output with no demonstrated impact. A CVE in a dependency we do not reach is not a finding; show the path

## Safe harbour

We will not pursue or support legal action against anyone who reports in good
faith under this policy, stays within scope, and does not access, modify or
retain data belonging to anyone else.
