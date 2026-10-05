"""Generate the Go-vs-pgmpy belief-runtime parity fixture (ADR-0134, gibson#377).

`internal/engine/brain/beliefvi` is the native Go port of this package's exact
variable-elimination engine (`infer.py`). `test_parity.py` already proves
`infer.query` agrees with `pgmpy.VariableElimination` to 1e-12; this script
generates the SAME evidence/query cases as JSON so a Go test
(`beliefvi.TestPgmpyParity`) can assert its own answers agree with `infer.py`'s
(and therefore, transitively, with pgmpy's) to the same 1e-12 tolerance —
without either linking pgmpy into the Go binary or shipping it anywhere near a
runtime image (ADR-0134: pgmpy is the offline parity oracle only).

    python sidecar/belief/gen_parity_fixture.py \\
        internal/engine/brain/beliefvi/testdata/parity.json.gz
    go test ./internal/engine/brain/beliefvi/... -run TestPgmpyParity -v

The fixture is checked in, so `go test ./...` runs the parity test with no
Python (gibson#714). The fixture carries `reference_digest`: the SHA-256 of the
files in REFERENCE_FILES below. The Go test `TestParityFixtureIsCurrent`
computes the same digest from the same files and fails when they differ. So a
change to the reference needs a new fixture in the same change.

This needs no pgmpy import at all — it calls `infer.query` (numpy only), which
is exactly the reference `test_parity.py` already holds to pgmpy. The CI
workflow (`belief-sidecar.yml`) additionally re-runs `test_parity.py` itself
(pgmpy installed) on every PR touching this directory, so a break in the
numpy engine's OWN agreement with pgmpy is caught there; this script's output
is what carries that already-proven agreement over to the Go side.
"""

from __future__ import annotations

import gzip
import hashlib
import itertools
import json
import os
import random
import sys
from typing import Dict, List

import infer
from model import STATES

HERE = os.path.dirname(os.path.abspath(__file__))

# The files that decide what the fixture holds: this generator, the inference
# engine, the model loader and the shipped model. The Go test hashes the same
# list in the same order (parity_test.go, parityReferenceFiles).
REFERENCE_FILES = (
    "gen_parity_fixture.py",
    "infer.py",
    "model.py",
    "models/base-v1.json",
)


def reference_digest() -> str:
    """SHA-256 over each reference file: its name, a NUL, its bytes, a NUL."""
    h = hashlib.sha256()
    for name in REFERENCE_FILES:
        with open(os.path.join(HERE, name), "rb") as fh:
            h.update(name.encode("utf-8"))
            h.update(b"\0")
            h.update(fh.read())
            h.update(b"\0")
    return h.hexdigest()


def _load_base() -> dict:
    with open(os.path.join(HERE, "models", "base-v1.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _factors(cpds: Dict[str, dict]):
    return [
        infer.cpd_to_factor(v, s["values"], s.get("evidence", []), s.get("evidence_card"))
        for v, s in cpds.items()
    ]


def _case(cpds: Dict[str, dict], query_var: str, evidence: Dict[str, str]) -> dict:
    got = infer.query(_factors(cpds), query_var, evidence)
    return {
        "cpds": cpds,
        "query_var": query_var,
        "evidence": evidence,
        "expected": got,
    }


def _random_network(rng: random.Random, n_vars: int):
    """Mirrors test_parity.py's _random_network exactly (same algorithm, same
    call pattern) so a fixed seed reproduces the same network here as there.
    """
    variables = [f"v{i}" for i in range(n_vars)]
    edges = []
    cpds: Dict[str, dict] = {}
    for i, var in enumerate(variables):
        candidates = variables[:i]
        n_parents = rng.randint(0, min(3, len(candidates)))
        parents = rng.sample(candidates, n_parents)
        edges.extend((p, var) for p in parents)
        columns = 2**n_parents
        false_row, true_row = [], []
        for _ in range(columns):
            p_true = rng.uniform(0.01, 0.99)
            false_row.append(1.0 - p_true)
            true_row.append(p_true)
        spec: dict = {"values": [false_row, true_row]}
        if parents:
            spec["evidence"] = parents
            spec["evidence_card"] = [2] * n_parents
        cpds[var] = spec
    return variables, edges, cpds


def generate() -> List[dict]:
    cases: List[dict] = []

    base = _load_base()
    cpds = base["cpds"]
    observable = [v for v in base["variables"] if not cpds[v].get("evidence")]

    # The shipped artifact, every full evidence assignment, all three query vars.
    for query_var in ("juicy", "exploitable", "reachable"):
        for assignment in itertools.product(STATES, repeat=len(observable)):
            evidence = dict(zip(observable, assignment))
            evidence.pop(query_var, None)
            cases.append(_case(cpds, query_var, evidence))

    # The shipped artifact, every partial evidence subset, query_var="juicy".
    for size in range(len(observable) + 1):
        for subset in itertools.combinations(observable, size):
            for assignment in itertools.product(STATES, repeat=size):
                evidence = dict(zip(subset, assignment))
                cases.append(_case(cpds, "juicy", evidence))

    # Random networks, mirroring test_parity.py's test_random_networks_match_pgmpy.
    for seed in range(25):
        rng = random.Random(seed)
        variables, _edges, rcpds = _random_network(rng, rng.randint(3, 9))
        query_var = rng.choice(variables)
        observable_r = [v for v in variables if v != query_var]
        rng.shuffle(observable_r)
        evidence = {v: rng.choice(STATES) for v in observable_r[: rng.randint(0, len(observable_r))]}
        cases.append(_case(rcpds, query_var, evidence))

    return cases


def fixture() -> dict:
    """The fixture document. Each case names its network, so the fixture holds
    each network one time and not one time for each case."""
    networks: Dict[str, dict] = {}
    names: Dict[int, str] = {}
    cases = []
    for case in generate():
        cpds = case["cpds"]
        name = names.get(id(cpds))
        if name is None:
            name = "base" if not networks else f"random-{len(networks) - 1}"
            names[id(cpds)] = name
            networks[name] = cpds
        cases.append(
            {
                "network": name,
                "query_var": case["query_var"],
                "evidence": case["evidence"],
                "expected": case["expected"],
            }
        )
    return {"reference_digest": reference_digest(), "networks": networks, "cases": cases}


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print("usage: gen_parity_fixture.py <path of parity.json.gz>", file=sys.stderr)
        return 2
    body = json.dumps(fixture(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    # mtime=0 and no file name in the header: the same input gives the same bytes.
    with open(argv[1], "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            gz.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
