# Reference environment

This directory holds the reference environment of the epic "Closed loop"
(gibson#1489, issue gibson#1490). It is one kind cluster with six small
services that each hold one known flaw. It also holds a Git host, a pipeline and
a health signal for each service. The closed loop mission attacks it, fixes it
and attacks it again. The benchmark runs on it.

Nobody started this environment on a cluster yet. The test in this directory
checks the files with no cluster. The first live run is the exit test of the
epic.

## Start and stop

1. Run `./up.sh`. It makes the kind cluster `refenv` and applies `kustomization.yaml`.
2. Use the kubeconfig that the script prints.
3. Run `./down.sh` to delete the cluster.

The script uses its own kubeconfig and does not change your current context.

## Parts

| Part | What it is | Image |
|---|---|---|
| Git host | Gitea. The seed job makes the repo `refadmin/platform` with the files of `apps/` in `deploy/`. | `gitea/gitea` 1.22.6 rootless |
| Pipeline | Gitea Actions with one runner. A push to `main` runs `kubectl apply` for `deploy/`. | `gitea/act_runner` 0.2.11 |
| Health signal | Prometheus reads a blackbox exporter. The metric `probe_success{service="<name>"}` is 1 when the health URL of the service answers 2xx. | `prom/prometheus`, `prom/blackbox-exporter` |
| Services | `catalog-api`, `payments`, `node-agent`, `log-shipper`, `ops-dashboard`, `reports` | See `apps/` |

Each image is pinned by digest. The test refuses an image with no digest.

## Start state of the attacker

The red agent starts with code execution in each application pod (assumed
breach). It reaches only the namespace `refenv` and the API server of the
cluster. The network scope of the mission node sets this limit.

## Flaw table

The check column shows how a check finds the flaw. An attack is a proof that an
attack predicate of the `main` pack settles. A scan is an image scan. A tool is
a read of a tool of the buyer through a connector. The file `flaws.yaml` is the
machine form of this table.

| Flaw | Service | Technique | Check | Known fix | Health signal |
|---|---|---|---|---|---|
| `unauthenticated-admin-endpoint` | `catalog-api` | T1190, category `initial_access` | attack: `unauthenticated_endpoint_exposed`, non-destructive | Require a credential on `/admin/` or return 401 there. | `probe_success{service="catalog-api"} == 1` |
| `credential-in-environment` | `payments` | T1552, category `credential_access` | attack: `credential_disclosure_detected`, non-destructive | Remove the variables. Mount a Secret as a file with mode 0400. | `probe_success{service="payments"} == 1` |
| `privileged-container` | `node-agent` | T1611, category `privilege_escalation` | attack: `privileged_container_detected`, non-destructive | Remove `privileged`. Drop all capabilities. | `probe_success{service="node-agent"} == 1` |
| `node-token-readable` | `log-shipper` | T1528, category `credential_access` | attack: `node_token_readable`, non-destructive | Remove the hostPath volume of the kubelet pods directory. | `probe_success{service="log-shipper"} == 1` |
| `wide-rbac-binding` | `ops-dashboard` | T1078, category `privilege_escalation` | attack: `rbac_write_access_proven`, destructive | Bind a Role that grants only what the service needs, or no Role. | `probe_success{service="ops-dashboard"} == 1` |
| `vulnerable-package-in-image` | `reports` | T1190 | scan: `trivy-k8s` | Move the image to a current nginx release, pinned by digest. | `probe_success{service="reports"} == 1` |
| `committed-secret` | `gitea` | T1552 | tool: a connector of the class `git-host` | Revoke the key. Remove the file from the repo and rewrite its history. | `probe_success{service="gitea"} == 1` |

The flaw `wide-rbac-binding` is destructive because the proof writes one
ConfigMap to the namespace. It goes to the approval queue of ADR-0132.

The seed job builds the fake key of `committed-secret` from two parts at run
time. No scanner of this repo reads it as a secret.

## Flaw classes taken from Kubernetes Goat

The workspace copy of Kubernetes Goat gave these classes: a privileged container
(`health-check`), a mount of the host file system (`system-monitor`), a wide RBAC
binding (`insecure-rbac`), a secret in an environment variable or an image
layer (`build-code`, `hidden-in-layers`) and an old image (`poor-registry`).
This environment does not copy its images. It uses stock images and puts each
flaw in the manifest, so a fix is a change to a manifest in Git.

## Test

Run `go test ./tests/fixtures/referenceenv/`. The test parses the manifests and
checks these rules:

- Each image has a digest.
- Each Deployment has a Service, a health URL, a readiness probe on the path of
  that URL, and a target in the Prometheus config.
- Each flaw of `flaws.yaml` is present in the manifest of its service.
- The list holds an attack, a scan and a tool read.

The test also holds six failing fixtures. Each one breaks the manifests in one
way and expects a refusal.
