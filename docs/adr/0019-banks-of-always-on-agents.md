# Banks of always-on agents: long-lived single-owner sandboxes, per-turn task grants, scorer-closed jobs

## Status

Proposed (2026-09-01). Amends [ADR-0016](0016-sandboxed-agent-dispatch.md)
decision 1 (one mission run, one sandbox) and supersedes gibson#1621 decision 12
(a hosted Claude agent runs on an API key, never on a subscription). Tracked by
the epic gibson#1706. Human sign-off is required.

The epic and the design glossary call this ADR-0017. That number was already
taken in this repo by the time the epic was written
([0017-tools-are-manifest-seeded-components.md](0017-tools-are-manifest-seeded-components.md)),
so the file is numbered 0019. The content is the one the epic describes.

## Context

ADR-0016 gives the platform one shape for a code-executing agent: one mission
run launches one ephemeral gVisor sandbox, the agent runs to a terminal result,
and setec tears the sandbox down. That shape works. The `zerocool` and `claude`
catalog agents run this way today.

The owner asked for a second shape (2026-09-01). A person or a tenant declares
"I want N Claude Code instances". The daemon keeps N members running. People,
other agents, tools and mission nodes give a member structured jobs. A job is
one Claude Code conversation with its own worktrees. It stays open through
back-and-forth with a verification agent until a scorer closes it. Then the
member cleans up and reports idle.

The one-shot shape cannot do this. It has no input path after launch, it ends
at the first result, and its single task grant dies with the run. A long-lived
member serves many dispatches over its life, so the identity and authorization
rules of ADR-0016 need an amendment, not a replacement.

The design was grilled on 2026-09-01 and recorded in the glossary of
`zerocool-plugins/CONTEXT.md`. The terms *Bank*, *Member*, *Job*, *Close*,
*Per-turn grant* and *Job node* in gibson `CONTEXT.md` carry the same wording.

## Decision

### 1. Bank and member

A **bank** is a declarative, daemon-reconciled pool of always-on Claude Code
instances. It has one owner, a desired count, a login shape, an image and a
model, a repository template, an idle policy and a spill policy.

A **member** is one instance in a bank. It is a long-lived gVisor sandbox
(ADR-0016 decision 4) owned by one principal. A member is an always-on mission
the owner originated (ADR-0063). The owner is a person, or the tenant when the
bank runs on the tenant API key. A member is never shared across owners: a
subscription sign-in belongs to one person, and a per-turn grant names one
dispatch. The reaper leaves a member alone. It is finished only when the bank
scales down or the owner deletes the bank.

The daemon launches members until the desired count runs, relaunches a dead
member, and holds a member at `needs sign-in` until its owner completes the
in-sandbox login. A member is sized small at idle: the manifest gives a low
request and a higher limit.

### 2. Per-turn task grants

ADR-0016 decision 2 stands: a sandbox holds only the scope of its own dispatch.
A member serves many dispatches over its life, so the rule is applied per turn.

- **Every input carries the grant of its own dispatch.** A job, an answer, a
  verifier report and a chat turn each arrive with the task grant the daemon
  minted for that dispatch. Every tool call in that turn uses that grant.
- **The member base grant covers lifetime RPCs only.** Heartbeat, job pull,
  sign-in relay, checkpoint and archive. It cannot observe, submit findings,
  call tools or delegate. Those need the turn's grant.
- **The Gibson MCP server runs over streamable HTTP on localhost inside the
  sandbox.** The driver holds the inbox subscription and swaps the grant before
  each turn. A stdio MCP server cannot do this: Claude Code spawns a stdio
  server once per session and owns its lifetime, so the credential it started
  with is the credential it keeps. There is no hook to replace it between
  turns, and restarting the server drops the tool state mid-conversation.
  A localhost HTTP server is one process the driver owns. It reads the current
  grant from the driver on every request.

### 3. Jobs

A **job** is the unit of work a member holds. The first structured input opens
it. A job owns one persistent Claude Code session (transcript on disk, reopened
with `--resume`) and its own worktrees. Unrelated jobs never share a
conversation or a worktree. A chat turn from the console is a job with only a
goal. Nothing arrives at a member as a bare string.

A job has four states: `OPEN`, `WORKING`, `WAITING`, `CLOSED`. `WAITING` means
the job asked a question and the next input is the answer.

**The worker never closes its own job.** A scorer does: a verification agent,
a person, or the job node after its acceptance step. The scorer sends
`CloseJob(job_id, verdict, score)`. Then the driver runs one wrap-up turn,
removes the worktrees, archives the transcript to the session store, reports
deliverables and verdict on the run, and drops the job. A job idle past the
bank's stale limit closes with verdict `abandoned`. Nothing else deletes a
worktree.

### 4. Login shapes

All three login shapes are offered: **subscription**, **Anthropic API key**,
and **third-party provider** (Amazon Bedrock, Google Vertex, Microsoft
Foundry). The platform offers all three because the Claude Code terms forbid
restricting a built-in method.

The Claude Code documentation, Legal and compliance, section "Can customers
offer Claude Code in their products?" (read 2026-09-01), says:

> Unless we've mutually agreed otherwise, preinstalling or running Claude Code
> in your products or services (e.g. in hosted sandboxes or other agent
> infrastructure) requires agreeing to our Commercial Terms of Service and
> complying with the conditions below:
>
> - **The Claude Code binary must not be modified.** Claude Code must be
>   installed and run as published by Anthropic, and customers may not remove,
>   disable, or restrict any authentication method built into it (including
>   methods that permit signing in with a Claude account or the user's own API
>   key).
> - **Customers may not pay for, resell, or intermediate Claude usage on their
>   end users' behalf.** Each end user must authenticate with their own
>   Anthropic API key, Claude subscription plan credentials, or 3P inference
>   provider credential (Amazon Bedrock, Google Cloud's Agent Platform,
>   Microsoft Foundry). That usage is billed directly to the end user under
>   their own agreement with Anthropic or, for third-party inference providers,
>   with the applicable provider.

The same page, section "Authentication and credential use", adds the third
condition:

> Moreover, developers may not collect, store, or intermediate Claude.ai
> credentials or session tokens — sign-in to a Claude account must complete
> through Anthropic's own flow.

The three conditions map to three rules:

1. **The binary is not modified and no login method is removed.** The driver
   spawns the published `claude` CLI (decision 5). The bank offers every shape.
2. **The platform never pays for or intermediates usage.** An API key and a
   third-party credential come from the tenant provider configuration and the
   manifest `credentials` block, and the tenant pays. A subscription is the
   person's own.
3. **A subscription is never stored by the platform.** The person signs in
   inside the sandbox, in the unmodified `claude` binary, through Anthropic's
   own flow. The console relays the sign-in URL and the code prompt. The daemon
   never sees the OAuth token. A one-shot instance cannot use a subscription,
   because no person is present.

gibson#1621 decision 12 said a hosted Claude agent runs on an Anthropic API key
and never on a person's subscription. It read the headless-mode note ("bare
mode does not read `CLAUDE_CODE_OAUTH_TOKEN`") as a platform rule. The Legal
and compliance page says the opposite: a platform that hosts Claude Code may
let an end user sign in with their own subscription, in the unmodified binary,
through Anthropic's flow. Decision 12 is superseded by this decision.

### 5. The driver spawns the unmodified `claude` CLI

The member driver runs the published `claude` binary with `-p`,
`--output-format stream-json` and `--input-format stream-json`. It never uses
the Agent SDK. The hosting exemption in the terms names the binary, and the
Agent SDK is API-key only.

### 6. Permission posture inside the sandbox

A job runs Claude Code with `--dangerously-skip-permissions`. The gVisor
sandbox and the per-turn grant are the controls. The image is non-root, which
the flag requires.

Outward side effects are **deliverables** the driver performs at wrap-up under
the job's declared deliverable and the base-grant connector token: push, merge
request, finding status. Claude commits on the job branch and never holds the
token.

Questions to a person go through one Gibson MCP tool, `ask`, wired as
`--permission-prompt-tool`. The job enters `WAITING` and the next input is the
answer. The inbox is daemon-owned and pulled outbound by the sandbox. There is
no setec `Attach` and no inbound connection.

### 7. The verify loop lives in the job node executor

`NODE_TYPE_JOB` is the mission node that drives a job on a bank. Its executor
runs the verify loop internally: open the job, dispatch the acceptance step to
the declared verifier component, on failure send the verifier report as the
next input to the same job, repeat up to the node's retry policy, then
`CloseJob` with verdict and score. The mission graph stays a DAG. There are no
loop edges. Only the job node executor and a person may call `CloseJob`.

## Consequences

- **Two new authz objects: `bank` and `job`.** `can_send` on a bank decides who
  may give a member input. `can_close` on a job decides who may score it. The
  registry gains `BankService` and `JobService` rules. The model change ships
  with `make authz-registry` output in the same PR.
- **New RPC surface.** `BankService` (create, get, list, update, delete, list
  members), `JobService` (open, send input, close, get, list, pull, heartbeat),
  and the harness callback inbox RPCs (`SubscribeInput`, `ask`). The protos
  live in the OSS SDK as `gibson.bank.v1` and `gibson.job.v1`.
- **Heartbeat carries member status.** `jobs in flight`, `cap`, `busy` or
  `idle`, and `needs sign-in`. The console shows it on `ListRunningAgents`.
- **The dispatch gate stays.** A member is dispatched only if the owner's
  tenant has `tenant_enabled` on the agent component (ADR-0016 decision 3).
- **The exit test is real-model and non-blocking.** `exit-test-bank.yml` runs
  on `main` and on a schedule with a real key from a repository secret. It
  asserts lifecycle and deliverables, never model text. It feeds the scorecard
  and blocks nothing (ADR-0012).
- **Cost.** A member is a resident sandbox. A bank of N members holds N
  sandboxes at idle. The idle sizing in the manifest and the SandboxClass
  request and limit split keep that small, and the tenant pays for the model.
- **A long-lived sandbox is a longer exposure.** One compromised member reaches
  one owner's jobs for the life of the member, not one run. The per-turn grant
  bounds what the member can do at any moment, and the base grant cannot reach
  tenant data. This is the trade the owner accepted for an always-on agent.

## Alternatives considered

- **One sandbox per job.** Rejected. A job is a conversation that waits on a
  person or a verifier for minutes or hours. A fresh sandbox per job loses the
  warm clone cache and pays a launch per turn.
- **A stdio Gibson MCP server with one lifetime grant.** Rejected. A lifetime
  grant is a standing credential, which ADR-0016 decision 2 forbids. A stdio
  server cannot swap credentials between turns.
- **The Agent SDK instead of the CLI.** Rejected. The SDK is API-key only and
  the hosting exemption names the binary.
- **Storing the subscription token in the tenant store.** Rejected. The terms
  forbid a platform to collect, store or intermediate Claude.ai credentials.
- **The worker closes its own job.** Rejected. A worker that judges its own
  work always passes. The scorer is a separate principal.
