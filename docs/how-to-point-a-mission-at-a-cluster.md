# How to point a mission at a Kubernetes cluster

Three records, written once each, in this order. They are deliberately
separate: the secret holds the credential, the Target says what is being
assessed, and the mission says which components may be handed which secret.

Do this for the second cluster without reading any issue's history. If a step
here does not work, the step is wrong, not the reader.

## 1. Store the kubeconfig as a tenant secret

```bash
kubectl --context <cluster> config view --raw --minify \
  | gibson secret set cred:<cluster>-kubeconfig --stdin
```

The `cred:` prefix is the category and is used verbatim: there is no
`--category` flag, because a category that disagreed with the prefix would
write a key nobody can read.

Pipe it. Do not write the kubeconfig to a file in a repository first.

The cluster tools refuse a kubeconfig that needs an exec credential plugin, an
`auth-provider`, a `tokenFile`, or a file path for a certificate — each of
those would make the scanner run a program or read a file of the tenant's
choosing. `--raw --minify` inlines the token and the CA for the one context,
which is the shape they accept.

## 2. Register the Target

```bash
gibson target create \
  --name <cluster> \
  --type kubernetes \
  --url https://<api-server>:6443
```

The Target names **what** is assessed. It carries no credential and no
authentication shape: `credential_id`, `secret_name` and `auth_type` were
removed from the record by owner decision 2026-10-01, and
`internal/infra/types/target.go` says not to re-add them. The mission declares
the credential instead, which is step 3.

`--name` is what a mission's `{{target.name}}` binds to, and the cluster tools
use it to label the result. The API server is never found through it; the
kubeconfig does that.

## 3. Submit the mission, naming the secret

The mission takes four parameters and no others.
`internal/platform/missioncatalog/missions/cluster-assessment.cue` declares
them, and an unknown key is refused rather than dropped, so a typo cannot read
as a value that bound:

| parameter | value |
|---|---|
| `kubeconfigSecret` | `cred:<cluster>-kubeconfig`, from step 1 |
| `bank` | the bank of always-on members the two jobs run on |
| `forgeConnector` | the connector holding the forge credential |
| `manifestsProject` | the project path holding the cluster's manifests |

Read what the platform ships, and what each mission needs:

```bash
gibson mission catalog list
gibson mission catalog show cluster-assessment
```

`show` prints the mission's CUE verbatim, so what the daemon will run can be
read rather than trusted.

Then submit it:

```bash
gibson mission submit \
  --catalog cluster-assessment \
  --target <target-uuid> \
  --param kubeconfigSecret=cred:<cluster>-kubeconfig \
  --param bank=<bank> \
  --param forgeConnector=<connector> \
  --param manifestsProject=<group>/<repo>
```

The daemon renders it from the definition compiled into its own binary
(ADR-0018), so the graph is the checked-in one and not a copy. Never copy the
mission's CUE out of this repository and submit the copy: a second definition of
one mission is what ADR-0027 forbids, and it would silently stop tracking the
checked-in one.

`--target` is required here. A catalog mission declares no target, which is what
makes it reusable across clusters, and the target binds from the id you pass and
from nowhere else — no parameter can supply one.

An agent submits the same mission through
`mission.CreateMissionOpts{CatalogMission: ..., CatalogParams: ...}` in the SDK.
Both paths call the same renderer, so both run the same graph.

Inside the mission, the declaration is one line:

```cue
secrets: tools: [_params.kubeconfigSecret]
```

Every tool node in the run may be handed that secret. The daemon resolves the
name as itself at dispatch and the value arrives in the tool's environment as
`GIBSON_SECRET_CRED_<CLUSTER>_KUBECONFIG` — upper-cased, with every character
outside `A-Z`, `0-9` and `_` folded to `_`. `secretenv.Key` in the SDK is the
one copy of that rule, and both the daemon that writes the variable and the
tool that reads it call it.

Each tool node also passes the secret's **name** in its input, because a tool
cannot guess which of the secrets it was handed is the kubeconfig:

```cue
toolConfig: {
	toolName: "kube-bench"
	input: {
		target:           "{{target.name}}"
		kubeconfigSecret: _params.kubeconfigSecret
	}
}
```

## Why a name in the input and a value in the environment

A tool's input JSON is captured with the tool call and stored with it. A
mission definition is stored, listed, rendered, validated and displayed. A
credential written into either would outlive the dispatch in a place people
read.

The environment does not. `TestSecretValue_ReachesTheToolAndLeaksNowhereElse`
in `internal/engine/harness` asserts that as one property: a sentinel value
reaches the tool and appears in none of the four surfaces above.

## What fails, and how it reads

| What you did | What happens |
|---|---|
| Named a secret the tenant does not hold | The dispatch is refused, naming the tool and the secret. The tool does not run. |
| Declared the secret for a different scope | The tool reports the input field and the variable it looked for. |
| Put the kubeconfig's content in `kubeconfigSecret` | Refused. The field holds a name. |
| Two declared names that fold to one variable | The dispatch is refused rather than letting one name win. |

Every one of those is an error, not an empty result. A security tool that
cannot reach the cluster must never report a clean scan.

## Related

- `docs/secrets.md` — where every credential in the control plane lives
- `internal/platform/missioncatalog/missions/cluster-assessment.cue` — the mission
- `internal/server/daemon/api/catalog_missions.go` — the two reads the CLI calls
- `internal/infra/types/target.go` — why a Target carries no credential
