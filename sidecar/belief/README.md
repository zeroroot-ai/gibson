# Belief-field sidecar (gibson#750, ADR-0005)

This is the **belief-field sidecar**: a small Python service that runs **exact,
read-only** Bayesian inference (variable elimination) over an attack-path
network and returns the three belief-field components for a host —
`P(juicy)` / `P(exploitable)` / `P(reachable)`.

The Go daemon never does probability math itself (ADR-0005 §1: "LLMs are bad
probability calculators; a Bayes net is calibrated, fast, free"). The daemon's
`brain.PgmpyBeliefProvider` POSTs host evidence here on **evidence change**
(never per clock tick — `internal/brain/belief.go::BeliefSystem` only re-scores
when the score moves), and records the returned model **version** on the host so
replay reproduces.

## Invariants (ADR-0005)

- **Exact inference only** (variable elimination, `infer.py`) — never sampling.
  Deterministic and reproducible, which 1:1 replay / the Scroller require.
- **Read-only at runtime.** The server loads versioned artifacts and answers
  posteriors; it never trains or mutates a model online (online learning would
  drift the field mid-mission and break replay). Training is a separate offline
  batch job (out of scope here; see ADR-0005 §4).
- **Versioned artifacts.** Each model file declares its `version`. A mission pins
  the version it ran under (`Mission.BeliefModel`); a `version` in the request
  selects that artifact, so replay re-loads the exact model.
- **Novel nodes → the caller's LLM fills the gap, not the math** (ADR-0005 §6).
  When evidence references a variable the network has no table for, the response
  flags it under `novel`; the daemon may re-POST with an LLM-estimated `prior`.

## Wire protocol

`POST /score` with:

```json
{
  "version": "base-v1",
  "evidence": {"open_ports": [22, 443], "services": ["22/ssh", "443/https"], "reachable": true},
  "priors": {"10.0.0.5": {"juicy": 0.3, "exploitable": 0.4, "reachable": 1.0}}
}
```

Response:

```json
{"version": "base-v1", "juicy": 0.61, "exploitable": 0.74, "reachable": 1.0, "novel": []}
```

`GET /healthz` → `200 ok` once a model is loaded.
`GET /version` → `{"versions": ["base-v1", ...], "default": "base-v1"}`.

## Model artifact format

A model is a JSON file under `models/<version>.json` declaring a discrete
Bayesian network: variables (each binary: `true`/`false`), directed edges, and a
CPT per variable. The three query variables MUST be present: `juicy`,
`exploitable`, `reachable`. See `models/base-v1.json` for the shipped minimal
base model and `model.py` for the schema.

OSS ships the minimal `base-v1`; the curated commercial base model (vendor
red-team + public CVE/MITRE ATT&CK, never tenant data — ADR-0003/0005 §7) is
served by the commercial layer and dropped in as additional `models/*.json`.

## Dependencies: numpy, and nothing else

Inference used to run on `pgmpy==0.1.26`. It no longer does.

`pgmpy` requires `torch`, and `torch` brings `triton`, `xgboost`,
`scikit-learn`, `pandas`, `scipy`, `statsmodels` and `sympy`. Three lines in
`requirements.txt` resolved to 44 packages and roughly 3 GB of a deep-learning
stack — shipped to production, in a security product, to marginalise a
seven-node binary network. None of it did any work: this service runs no
training, no autodiff and no tensor operations.

`infer.py` is the same algorithm — sum-product variable elimination — on numpy
alone, in about 200 lines. Variable elimination *is* exact inference, so this is
not an approximation of what pgmpy did; the elimination order changes the cost,
never the answer. `test_parity.py` asserts agreement with `pgmpy==0.1.26` to
1e-12 across the shipped artifact's entire evidence space and 25 randomly
generated networks. It runs in CI (`requirements-dev.txt` installs pgmpy there)
and skips locally when pgmpy is absent.

The on-disk CPD layout is unchanged — still pgmpy's `TabularCPD` column
ordering — so existing model artifacts load untouched.

Alongside that, the runtime image dropped its Debian userland for distroless.
The two together were 24 of the 25 open HIGH/CRITICAL code-scanning alerts on
the whole `gibson` repo, four of them CRITICAL in `perl-base`, in packages
nothing here invokes. Details in gibson#1436.

## Run

```bash
pip install -r requirements.txt
python -m server --models ./models --port 8087
```

Tests:

```bash
pip install -r requirements.txt pytest
python -m pytest test_model.py test_infer.py -q     # runtime dependency set

pip install -r requirements-dev.txt                 # adds pgmpy — dev only
python -m pytest test_parity.py -q                  # the pgmpy comparison
```

The daemon points at it via `GIBSON_BELIEF_SIDECAR_URL=http://127.0.0.1:8087/score`.
When that env var is unset the daemon uses the deterministic Go placeholder
provider (OSS-without-base-model), so the sidecar is optional at runtime.
