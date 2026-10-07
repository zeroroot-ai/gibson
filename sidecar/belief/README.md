# Belief-field reference implementation (ADR-0129, ADR-0134)

This package is the **offline reference implementation and pgmpy parity
oracle** for the belief-field inference algorithm — exact Bayesian inference
(variable elimination) plus the noisy-OR enablement-CPT decomposition
(ADR-0129). It is NOT a running service.

Belief inference itself runs **in-process, in Go**, in the daemon:
`internal/engine/brain/beliefvi` is a line-for-line port of the algorithm
here (`infer.py`, `noisy_or.py`, `ground.py`, `model.py`), used by
`brain.NativeBeliefProvider` (ADR-0134, gibson#377). The Python HTTP sidecar
this package used to run (`server.py`) and its image
(`gibson-belief-sidecar`) are retired — hard cutover, no HTTP round-trip left
anywhere in this seam.

## What stays, and why

- **`infer.py` / `noisy_or.py` / `ground.py` / `model.py`** stay as the
  reference implementation `beliefvi`'s Go answers are checked against.
  `test_parity.py` asserts `infer.query` agrees with `pgmpy`'s
  `VariableElimination` to 1e-12 (unchanged from before ADR-0134);
  `gen_parity_fixture.py` generates the same cases as a JSON fixture so a Go
  test (`beliefvi.TestPgmpyParity`) can assert the same 1e-12 agreement
  transitively, without pgmpy (or numpy) ever linking into the Go binary or
  any runtime image. The fixture is checked in at
  `internal/engine/brain/beliefvi/testdata/parity.json.gz`, so `go test ./...`
  runs the parity test with no Python. `beliefvi.TestParityFixtureIsCurrent`
  fails when a reference file changed and the fixture did not.
- **`models/base-v1.json`** stays canonical here — `braintrain`
  (`cmd/belief-trainer`, `internal/engine/braintrain`) and this package's own
  tests read it from this path. `internal/engine/brain/beliefvi` embeds a
  guarded byte-identical copy (`beliefvi/models/base-v1.json`,
  `TestDefaultArtifact_MatchesTheCanonicalPythonSource`) so the daemon binary
  needs no external model file for the default.
- **pgmpy** is a dev-only, CI-only dependency (`requirements-dev.txt`) — the
  offline parity oracle, never a deployed dependency, exactly as ADR-0134
  originally intended before the sidecar existed.

## What is gone

`server.py`, `test_server.py`, the `/score` / `/healthz` / `/version` HTTP
wire protocol, and `Dockerfile` (the `gibson-belief-sidecar` image and its
`gibson-images.yml` publish job). Nothing calls `resolveBeliefProvider`'s old
`GIBSON_BELIEF_SIDECAR_URL` env var any more. The daemon reads the current
belief version of each tenant from the platform Postgres (gibson#615), and a
tenant with no version uses the embedded `base-v1` model.

## Ground-slice inference (ADR-0129, gibson#288)

`noisy_or.py` and `ground.py` are the multi-node counterpart to the
single-host model above: given a bounded slice (gibson#287 — a set of nodes,
each with its own declared belief variables, plus the enablement edges wiring
one node's variable into another's), `ground.solve_slice` grounds it into one
factor set and returns exact posteriors for every `(node, variable)` pair.
`beliefvi.GroundSlice` / `beliefvi.SolveSlice` are the Go port, exercised by
the same test shapes as `test_ground.py` / `test_noisy_or.py`.

A node with many enablement-edge parents would otherwise need a CPT with
`2**N` columns. `noisy_or.noisy_or_factors` builds the same conditional
distribution as an `O(N)` DECOMPOSITION of small factors instead (the standard
"parent divorcing" construction: one mechanism variable per cause, one leak
variable, and a chain of pairwise OR gates) — an exact reformulation, not an
approximation, proven by parity against the brute-force full table for small
`N` in `test_noisy_or.py`. `ground.py` treats an intra-node dependency (e.g.
Host's `reachable -> exploitable -> juicy` funnel) and a cross-node
enablement cause identically: both are just independent noisy-OR causes of
the variable they feed, so one mechanism covers what used to be a
node-specific hardcoded CPT and what ADR-0129 newly adds.

Grounding a *live* bounded slice (as opposed to running the algorithm on
hand-built `NodeSpec`/`EnablementCause` values in a test) still needs two
numbers the ontology has no source for yet: which of a target node's own
declared variables an incoming enablement edge feeds, and the noisy-OR
strength/leak for that contribution (ADR-0137 — a learned Beta posterior per
edge-type, gibson#346/#333). `beliefvi.GroundSlice`/`SolveSlice` are ready;
`internal/server/daemon/belief_provider.go`'s `resolveSliceBeliefProvider`
documents exactly what still blocks wiring a real
`brain.SliceBeliefProvider` from them.

## Model artifact format

A model is a JSON file under `models/<version>.json` declaring a discrete
Bayesian network: variables (each binary: `true`/`false`), directed edges, and a
CPT per variable. The three query variables MUST be present: `juicy`,
`exploitable`, `reachable`. See `models/base-v1.json` for the shipped minimal
base model and `model.py` for the schema.

Gibson ships the minimal `base-v1`. The curated commercial base model (public
CVE, CISA KEV, EPSS and MITRE ATT&CK data, never tenant data — ADR-0089/0129)
lives in the closed `billing` repo. Its trainer image sets
`BELIEF_BASE_MODEL` to the model file (gibson#31). `cmd/belief-trainer` then
fits on that base, and a tenant with no version gets the base as its first
version through the trainer RPCs (gibson#788), so a new tenant starts on the
curated model.

## Dependencies: numpy, and nothing else

Inference used to run on `pgmpy==0.1.26`, then on a Python sidecar running
`infer.py` (numpy only), then — since ADR-0134 — in-process in Go. `pgmpy`
requires `torch`, and `torch` brings `triton`, `xgboost`, `scikit-learn`,
`pandas`, `scipy`, `statsmodels` and `sympy`: roughly 3 GB of a deep-learning
stack that never did any work here — this package runs no training, no
autodiff and no tensor operations of its own. It exists purely so the exact
answer `pgmpy` gives has something to check `infer.py` — and, transitively,
`beliefvi` — against.

`infer.py` is the same algorithm — sum-product variable elimination — on numpy
alone, in about 200 lines. Variable elimination *is* exact inference, so this is
not an approximation of what pgmpy did; the elimination order changes the cost,
never the answer. `test_parity.py` asserts agreement with `pgmpy==0.1.26` to
1e-12 across the shipped artifact's entire evidence space and 25 randomly
generated networks. It runs in CI (`requirements-dev.txt`, compiled from
`requirements-dev.in` with hashes, installs pgmpy there) and skips locally
when pgmpy is absent.

The on-disk CPD layout is unchanged — still pgmpy's `TabularCPD` column
ordering — so existing model artifacts load untouched, in Python or in Go.

## Run

```bash
pip install --require-hashes -r requirements.txt -r requirements-test.txt
python -m pytest test_model.py test_infer.py test_noisy_or.py test_ground.py -q     # reference implementation

pip install --require-hashes -r requirements-dev.txt   # adds pgmpy — dev only
python -m pytest test_parity.py -q                  # the pgmpy comparison

# The Go-vs-reference fixture is checked in. Make it again after a change to
# gen_parity_fixture.py, infer.py, model.py or models/base-v1.json.
python gen_parity_fixture.py ../../internal/engine/brain/beliefvi/testdata/parity.json.gz
go test ../../internal/engine/brain/beliefvi/... -run 'TestPgmpyParity|TestParityFixtureIsCurrent' -v
```
