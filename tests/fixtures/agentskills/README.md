# Agent Skill fixtures

These folders are the Agent Skills of the exit test `TestAgentSkills`. The tool
`pack` builds each folder into an OCI image and pushes it to a registry by digest.
The daemon then pulls the image by that digest.

## What the test needs from a registry

The registry must meet all of these rules.

1. It speaks HTTPS with a certificate that the daemon trusts.
2. It has a public address. The name must resolve to an address that is not
   private, loopback, link-local or carrier-grade NAT.
3. It serves a pull by digest, for example `ghcr.io/zeroroot-ai/name@sha256:<hex>`.
   A tag reference is refused.
4. It accepts the credential that the test gives it (`E2E_SKILL_REGISTRY_USERNAME`
   and `E2E_SKILL_REGISTRY_PASSWORD`), or it allows an anonymous pull.

## Why a plain HTTP local registry cannot serve it

The daemon pulls an Agent Skill for a tenant, and the tenant names the
registry. So the puller (`internal/engine/agentskill/pull.go`) has two limits
that no setting removes for a tenant:

- It refuses each request that is not HTTPS. A local registry on `http://` fails
  at the first request. The registry client would choose plain HTTP for a name
  such as `localhost`, so the check is in the transport.
- Its dialer refuses a private address after name resolution, for each
  connection and each redirect. A registry in the kind network (for example
  `172.18.255.251:5000`) has a private address, so the dial fails.

Only the operator path (`AllowPrivateAddresses`, used for the shared Agent
Skills of the platform) may use a private address, and it still needs HTTPS. The
exit test uses the tenant path, because it tests the tenant rules.

## Run the test from a workstation

1. Push the four images to a registry that meets the rules above. The CI job
   uses `ghcr.io` with the token of the run. The commands are in the step "Pack
   the Agent Skill folders" of `.github/workflows/exit-test-agent-skills.yml`.
2. Write the four `E2E_SKILL_REF_*` references, `E2E_SKILL_REGISTRY` and the
   credential into the env file that `run-e2e-job.sh` reads (`E2E_RUNNER_ENV_FILE`).
3. Run the job with `-test.run TestAgentSkills`.
