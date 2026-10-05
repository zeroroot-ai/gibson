"""Generate the Go-vs-pgmpy belief-runtime parity fixture (ADR-0134, gibson#377).

`internal/engine/brain/beliefvi` is the native Go port of this package's exact
variable-elimination engine (`infer.py`). `test_parity.py` already proves
`infer.query` agrees with `pgmpy.VariableElimination` to 1e-12; this script
generates the SAME evidence/query cases as JSON so a Go test
(`beliefvi.TestPgmpyParity`) can assert its own answers agree with `infer.py`'s
(and therefore, transitively, with pgmpy's) to the same 1e-12 tolerance —
without either linking pgmpy into the Go binary or shipping it anywhere near a
runtime image (ADR-0134: pgmpy is the offline parity oracle only).

    python sidecar/belief/gen_parity_fixture.py > /tmp/belief-parity.json
    GIBSON_BELIEF_PARITY_FIXTURE=/tmp/belief-parity.json \\
        go test ./internal/engine/brain/beliefvi/... -run TestPgmpyParity -v

This needs no pgmpy import at all — it calls `infer.query` (numpy only), which
is exactly the reference `test_parity.py` already holds to pgmpy. The CI
workflow (`belief-sidecar.yml`) additionally re-runs `test_parity.py` itself
(pgmpy installed) on every PR touching this directory, so a break in the
numpy engine's OWN agreement with pgmpy is caught there; this script's output
is what carries that already-proven agreement over to the Go side.
"""

from __future__ import annotations

import itertools
import json
import os
import random
import sys
from typing import Dict, List

import infer
from model import STATES

HERE = os.path.dirname(__file__)


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


def main() -> int:
    json.dump(generate(), sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
