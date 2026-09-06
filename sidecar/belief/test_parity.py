"""Parity: `infer.query` must agree with pgmpy's VariableElimination (gibson#1436).

The runtime image no longer ships pgmpy — that is the point of the change — so
this module skips itself when pgmpy is absent. It is the evidence that dropping
pgmpy did not change any answer, and it is meant to be run in a dev environment
that still has it:

    pip install 'pgmpy==0.1.26'
    pytest sidecar/belief/test_parity.py

Two kinds of check:

  * the shipped `models/base-v1.json` artifact, over every reachable evidence
    combination, against pgmpy;
  * randomly generated binary networks with random CPDs, so the comparison is
    not limited to the one topology we happen to ship.
"""

from __future__ import annotations

import itertools
import json
import os
import random
from typing import Dict, List, Tuple

import pytest

import infer
from model import STATES, BeliefModel, ModelArtifact

pgmpy = pytest.importorskip(
    "pgmpy", reason="pgmpy is intentionally absent from the runtime image"
)

from pgmpy.factors.discrete import TabularCPD  # noqa: E402
from pgmpy.inference import VariableElimination  # noqa: E402
from pgmpy.models import BayesianNetwork  # noqa: E402

TOLERANCE = 1e-12
HERE = os.path.dirname(__file__)


def _pgmpy_network(variables: List[str], edges, cpds: Dict[str, dict]) -> BayesianNetwork:
    net = BayesianNetwork(list(edges))
    net.add_nodes_from(variables)
    for var, spec in cpds.items():
        parents = spec.get("evidence", [])
        parent_card = spec.get("evidence_card", [2] * len(parents))
        net.add_cpds(
            TabularCPD(
                variable=var,
                variable_card=2,
                values=spec["values"],
                evidence=parents or None,
                evidence_card=parent_card or None,
                state_names={n: list(STATES) for n in [var, *parents]},
            )
        )
    net.check_model()
    return net


def _our_factors(cpds: Dict[str, dict]):
    return [
        infer.cpd_to_factor(
            var, spec["values"], spec.get("evidence", []), spec.get("evidence_card")
        )
        for var, spec in cpds.items()
    ]


def _compare(reference, factors, cpds, query_var: str, evidence: Dict[str, str]) -> None:
    """Compare one query. `reference` and `factors` are built once by the caller.

    Building them per comparison is what made the first version of this file
    take minutes: pgmpy's `BayesianNetwork` + `check_model` dominates, and these
    tests run hundreds of queries.
    """
    expected = float(
        reference.query(
            variables=[query_var], evidence=evidence, show_progress=False
        ).get_value(**{query_var: "true"})
    )
    actual = infer.query(factors, query_var, evidence)["true"]
    assert actual == pytest.approx(expected, abs=TOLERANCE), (
        f"query {query_var!r} | {evidence!r}: ours={actual!r} pgmpy={expected!r}"
    )


def _load_base() -> dict:
    with open(os.path.join(HERE, "models", "base-v1.json"), encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def base():
    """The shipped artifact, with both engines prepared once for the module."""
    raw = _load_base()
    edges = [tuple(e) for e in raw["edges"]]
    return {
        "raw": raw,
        "cpds": raw["cpds"],
        "reference": VariableElimination(
            _pgmpy_network(raw["variables"], edges, raw["cpds"])
        ),
        "factors": _our_factors(raw["cpds"]),
        "observable": [v for v in raw["variables"] if not raw["cpds"][v].get("evidence")],
    }


def test_shipped_artifact_matches_pgmpy_for_every_evidence_combination(base):
    # Root variables are the ones evidence can actually set (the sidecar only
    # ever observes reachable / port_* / svc_*), so enumerate over those.
    observable = base["observable"]
    for query_var in ("juicy", "exploitable", "reachable"):
        for assignment in itertools.product(STATES, repeat=len(observable)):
            evidence = dict(zip(observable, assignment))
            evidence.pop(query_var, None)
            _compare(base["reference"], base["factors"], base["cpds"], query_var, evidence)


def test_shipped_artifact_matches_pgmpy_with_partial_evidence(base):
    """Every subset of the observable variables, not just the full assignments."""
    observable = base["observable"]
    for size in range(len(observable) + 1):
        for subset in itertools.combinations(observable, size):
            for assignment in itertools.product(STATES, repeat=size):
                evidence = dict(zip(subset, assignment))
                _compare(base["reference"], base["factors"], base["cpds"], "juicy", evidence)


def _random_network(rng: random.Random, n_vars: int) -> Tuple[List[str], list, dict]:
    """A random DAG over binary variables with random, properly normalised CPDs."""
    variables = [f"v{i}" for i in range(n_vars)]
    edges: List[Tuple[str, str]] = []
    cpds: Dict[str, dict] = {}
    for i, var in enumerate(variables):
        # Parents come from earlier variables only, which makes the graph a DAG
        # by construction. Cap the in-degree so the CPT stays small.
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


@pytest.mark.parametrize("seed", range(25))
def test_random_networks_match_pgmpy(seed: int):
    rng = random.Random(seed)
    variables, edges, cpds = _random_network(rng, rng.randint(3, 9))

    query_var = rng.choice(variables)
    observable = [v for v in variables if v != query_var]
    rng.shuffle(observable)
    evidence = {
        v: rng.choice(STATES) for v in observable[: rng.randint(0, len(observable))]
    }
    reference = VariableElimination(_pgmpy_network(variables, edges, cpds))
    _compare(reference, _our_factors(cpds), cpds, query_var, evidence)


def test_belief_model_end_to_end_matches_pgmpy(base):
    """The whole `BeliefModel.score` path, not just the raw query."""
    raw = base["raw"]
    model = BeliefModel(ModelArtifact.from_dict(raw))

    evidence = {"reachable": True, "open_ports": [22, 443], "services": ["22/ssh"]}
    scored = model.score(evidence)

    reference = base["reference"]
    observed = {"reachable": "true", "port_22": "true", "port_443": "true", "svc_ssh": "true"}

    assert scored["reachable"] == pytest.approx(1.0, abs=TOLERANCE)
    for q in ("exploitable", "juicy"):
        expected = float(
            reference.query(
                variables=[q],
                evidence={k: v for k, v in observed.items() if k != q},
                show_progress=False,
            ).get_value(**{q: "true"})
        )
        assert scored[q] == pytest.approx(expected, abs=TOLERANCE)
