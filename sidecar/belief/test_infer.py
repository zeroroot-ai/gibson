"""Unit tests for the exact-inference engine (gibson#1436).

Numerical agreement with the pgmpy implementation this replaced lives in
`test_parity.py`. What is tested here is everything pgmpy used to reject on our
behalf: malformed artifacts, cyclic graphs, impossible evidence. Those checks
moved into `infer.check_model` / `BeliefModel`, so they need their own coverage
— dropping a dependency must not quietly drop its validation.

Run:  python -m pytest sidecar/belief/test_infer.py
"""

import math

import pytest

import infer
from model import BeliefModel, ModelArtifact

# P(a=true)=0.3, b|a with a clean analytic answer to check against.
SIMPLE = {
    "version": "t",
    "variables": ["reachable", "exploitable", "juicy"],
    "edges": [["reachable", "exploitable"], ["exploitable", "juicy"]],
    "cpds": {
        "reachable": {"values": [[0.7], [0.3]]},
        "exploitable": {
            "evidence": ["reachable"],
            "evidence_card": [2],
            "values": [[0.9, 0.2], [0.1, 0.8]],
        },
        "juicy": {
            "evidence": ["exploitable"],
            "evidence_card": [2],
            "values": [[0.95, 0.4], [0.05, 0.6]],
        },
    },
}


def _factors(cpds):
    return [
        infer.cpd_to_factor(
            v, s["values"], s.get("evidence", []), s.get("evidence_card")
        )
        for v, s in cpds.items()
    ]


def test_marginal_matches_hand_computation():
    """P(exploitable) = 0.7*0.1 + 0.3*0.8 = 0.31."""
    got = infer.query(_factors(SIMPLE["cpds"]), "exploitable", {})
    assert got["true"] == pytest.approx(0.31, abs=1e-12)
    assert got["false"] + got["true"] == pytest.approx(1.0, abs=1e-12)


def test_conditioning_on_a_parent_reads_the_cpd_column_directly():
    got = infer.query(_factors(SIMPLE["cpds"]), "exploitable", {"reachable": "true"})
    assert got["true"] == pytest.approx(0.8, abs=1e-12)


def test_conditioning_on_a_child_runs_bayes_backwards():
    """P(reachable | exploitable=true) = 0.3*0.8 / 0.31."""
    got = infer.query(_factors(SIMPLE["cpds"]), "reachable", {"exploitable": "true"})
    assert got["true"] == pytest.approx(0.24 / 0.31, abs=1e-12)


def test_evidence_on_the_query_variable_is_ignored_not_honoured():
    """Callers pre-strip this, but the engine must not silently return 1.0."""
    free = infer.query(_factors(SIMPLE["cpds"]), "exploitable", {})
    pinned = infer.query(
        _factors(SIMPLE["cpds"]), "exploitable", {"exploitable": "true"}
    )
    assert pinned == free


def test_elimination_order_does_not_change_the_answer():
    """Variable elimination is exact: the order is a cost choice, not a result choice."""
    factors = _factors(SIMPLE["cpds"])
    baseline = infer.query(factors, "juicy", {"reachable": "true"})
    for rotation in range(len(factors)):
        shuffled = factors[rotation:] + factors[:rotation]
        assert infer.query(shuffled, "juicy", {"reachable": "true"}) == pytest.approx(
            baseline, abs=1e-12
        )


def test_repeated_queries_are_bit_identical():
    """ADR-0005 replay: same input, same float64 bits, not merely 'close'."""
    factors = _factors(SIMPLE["cpds"])
    first = infer.query(factors, "juicy", {"reachable": "true"})
    for _ in range(5):
        assert infer.query(factors, "juicy", {"reachable": "true"}) == first


def test_impossible_evidence_raises_rather_than_normalising_noise():
    cpds = {
        "reachable": {"values": [[1.0], [0.0]]},  # reachable=true has probability 0
        "exploitable": {
            "evidence": ["reachable"],
            "evidence_card": [2],
            "values": [[0.9, 0.2], [0.1, 0.8]],
        },
        "juicy": {"values": [[0.5], [0.5]]},
    }
    with pytest.raises(ValueError, match="zero probability"):
        infer.query(_factors(cpds), "exploitable", {"reachable": "true"})


def test_check_model_rejects_an_unnormalised_cpd():
    cpds = {"juicy": {"values": [[0.5], [0.7]]}}
    with pytest.raises(ValueError, match="not normalised"):
        infer.check_model(_factors(cpds), ["juicy"])


def test_check_model_rejects_a_missing_cpd():
    cpds = {"juicy": {"values": [[0.5], [0.5]]}}
    with pytest.raises(ValueError, match="no cpd for declared variable"):
        infer.check_model(_factors(cpds), ["juicy", "reachable"])


def test_check_model_rejects_an_undeclared_parent():
    cpds = {
        "juicy": {
            "evidence": ["ghost"],
            "evidence_card": [2],
            "values": [[0.5, 0.5], [0.5, 0.5]],
        }
    }
    with pytest.raises(ValueError, match="undeclared parent"):
        infer.check_model(_factors(cpds), ["juicy"])


def test_check_model_rejects_a_cycle():
    cpds = {
        "juicy": {
            "evidence": ["exploitable"],
            "evidence_card": [2],
            "values": [[0.5, 0.5], [0.5, 0.5]],
        },
        "exploitable": {
            "evidence": ["juicy"],
            "evidence_card": [2],
            "values": [[0.5, 0.5], [0.5, 0.5]],
        },
    }
    with pytest.raises(ValueError, match="cyclic"):
        infer.check_model(_factors(cpds), ["juicy", "exploitable"])


def test_cpd_to_factor_rejects_a_table_of_the_wrong_shape():
    with pytest.raises(ValueError, match="expected"):
        infer.cpd_to_factor("juicy", [[0.5, 0.5], [0.5, 0.5]], ["a", "b"], [2, 2])


def test_belief_model_rejects_edges_that_disagree_with_the_cpds():
    """The redundant `edges` list is exactly what a stale artifact gets wrong."""
    raw = {
        **SIMPLE,
        # edges claim reachable -> juicy, the cpds do not.
        "edges": [["reachable", "exploitable"], ["reachable", "juicy"]],
    }
    with pytest.raises(ValueError, match="but edges give"):
        BeliefModel(ModelArtifact.from_dict(raw))


def test_belief_model_accepts_the_consistent_artifact():
    model = BeliefModel(ModelArtifact.from_dict(SIMPLE))
    out = model.score({"reachable": True, "open_ports": [], "services": []})
    assert out["reachable"] == 1.0
    assert 0.0 <= out["juicy"] <= 1.0
    assert math.isfinite(out["exploitable"])


def test_belief_model_needs_no_third_party_dependency_but_numpy():
    """The whole point of gibson#1436: the import graph must stay this small."""
    import sys

    for banned in ("pgmpy", "torch", "pandas", "scipy", "sklearn", "statsmodels"):
        assert banned not in sys.modules, f"{banned} was imported by the sidecar"
