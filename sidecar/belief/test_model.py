"""Unit tests for the belief sidecar's pure helpers + artifact loading.

These exercise the deterministic, pgmpy-free parts (evidence mapping, novel-node
detection, artifact validation). The full pgmpy inference path is covered by an
optional test that skips when pgmpy is not installed.

Run:  python -m pytest sidecar/belief/test_model.py
"""

import json
import os

import pytest

from model import (
    QUERY_VARS,
    ModelArtifact,
    evidence_to_observations,
    posteriors_from_marginals,
)

BASE = os.path.join(os.path.dirname(__file__), "models", "base-v1.json")


def test_evidence_maps_known_and_flags_novel():
    known = {"reachable", "port_22", "svc_ssh"}
    ev = {"open_ports": [22, 9999], "services": ["22/ssh", "9999/weirdsvc"], "reachable": True}
    obs, novel = evidence_to_observations(ev, known)
    assert obs == {"reachable": "true", "port_22": "true", "svc_ssh": "true"}
    # port_9999 and svc_weirdsvc are unknown -> novel (the LLM-prior path).
    assert "port_9999" in novel
    assert "svc_weirdsvc" in novel


def test_evidence_is_deterministic_and_order_stable():
    known = {"reachable", "port_22", "port_443"}
    a, _ = evidence_to_observations({"open_ports": [443, 22], "reachable": True}, known)
    b, _ = evidence_to_observations({"open_ports": [22, 443], "reachable": True}, known)
    assert a == b


def test_unreachable_sets_false():
    obs, _ = evidence_to_observations({"reachable": False, "open_ports": []}, {"reachable"})
    assert obs == {"reachable": "false"}


def test_posteriors_default_missing_to_zero():
    out = posteriors_from_marginals({"juicy": 0.6})
    assert out["juicy"] == 0.6
    assert out["exploitable"] == 0.0
    assert out["reachable"] == 0.0


def test_artifact_loads_and_has_query_vars():
    art = ModelArtifact.load(BASE)
    assert art.version == "base-v1"
    for q in QUERY_VARS:
        assert q in art.known_vars


def test_artifact_rejects_missing_query_var():
    bad = {"version": "bad", "variables": ["reachable", "exploitable"], "cpds": {}}
    with pytest.raises(ValueError):
        ModelArtifact.from_dict(bad)


@pytest.mark.parametrize("port_evidence", [[22], [22, 443], []])
def test_base_model_exact_inference_is_deterministic(port_evidence):
    pgmpy = pytest.importorskip("pgmpy")  # skip cleanly when the heavy lib is absent
    from model import BeliefModel

    art = ModelArtifact.load(BASE)
    m = BeliefModel(art)
    ev = {"open_ports": port_evidence, "services": [], "reachable": len(port_evidence) > 0}
    a = m.score(ev)
    b = m.score(ev)
    # Exact inference: identical evidence -> bit-identical posteriors (replay-safe).
    assert a == b
    assert a["version"] == "base-v1"
    for q in QUERY_VARS:
        assert 0.0 <= a[q] <= 1.0


def test_base_model_reachable_raises_belief():
    pytest.importorskip("pgmpy")
    from model import BeliefModel

    m = BeliefModel(ModelArtifact.load(BASE))
    low = m.score({"open_ports": [], "services": [], "reachable": False})
    high = m.score({"open_ports": [22, 443], "services": ["22/ssh", "443/https"], "reachable": True})
    assert high["exploitable"] > low["exploitable"]
    assert high["juicy"] > low["juicy"]
    # Reachable is directly observed evidence, so its component is exact 1.0/0.0.
    assert high["reachable"] == 1.0
    assert low["reachable"] == 0.0
