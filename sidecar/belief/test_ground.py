"""Unit tests for grounding a bounded slice (gibson#287) into one exact-VE
solvable network and returning per-node posteriors (gibson#288, ADR-0129).

Run:  python -m pytest sidecar/belief/test_ground.py
"""

import pytest

from ground import EnablementCause, NodeSpec, VariableSpec, ground_name, ground_slice, solve_slice


def test_ground_name_is_stable_and_qualified():
    assert ground_name("host-a", "reachable") == "host-a::reachable"


def test_rejects_a_separator_in_node_or_variable_names():
    with pytest.raises(ValueError, match="::"):
        ground_name("host::a", "reachable")
    with pytest.raises(ValueError, match="::"):
        ground_name("host-a", "re::achable")


def test_single_root_node_returns_its_leak_as_the_posterior():
    """A variable with no causes at all is exactly its own leak (background
    rate) — the same case noisy_or_factors handles for zero causes."""
    nodes = [NodeSpec(node_id="host-a", variables={"reachable": VariableSpec(leak=0.2)})]
    out = solve_slice(nodes, enablement=[])
    assert out["host-a"]["reachable"]["true"] == pytest.approx(0.2, abs=1e-9)


def test_intra_node_dependency_chain_matches_hand_computation():
    """The real Host funnel (ADR-0129): reachable -> exploitable -> juicy,
    expressed as three noisy-OR variables instead of one explicit 8-column
    CPT — this is the same shape the pre-PRM per-host model hardcoded.
    """
    nodes = [
        NodeSpec(
            node_id="host-a",
            variables={
                "reachable": VariableSpec(leak=0.3),
                "exploitable": VariableSpec(depends_on={"reachable": 0.8}, leak=0.05),
                "juicy": VariableSpec(depends_on={"exploitable": 0.9}, leak=0.0),
            },
        )
    ]
    out = solve_slice(nodes, enablement=[])

    p_reachable = 0.3
    # P(exploitable=true) = p_reachable * P(exploitable|reachable=true)
    #                      + (1-p_reachable) * P(exploitable|reachable=false),
    # each conditional given by the noisy-OR closed form.
    p_ex_given_r_true = 1.0 - (1.0 - 0.05) * (1.0 - 0.8)
    p_ex_given_r_false = 1.0 - (1.0 - 0.05)
    p_exploitable = p_reachable * p_ex_given_r_true + (1 - p_reachable) * p_ex_given_r_false

    p_juicy_given_ex_true = 1.0 - (1.0 - 0.0) * (1.0 - 0.9)
    p_juicy_given_ex_false = 1.0 - (1.0 - 0.0)
    p_juicy = p_exploitable * p_juicy_given_ex_true + (1 - p_exploitable) * p_juicy_given_ex_false

    assert out["host-a"]["reachable"]["true"] == pytest.approx(p_reachable, abs=1e-9)
    assert out["host-a"]["exploitable"]["true"] == pytest.approx(p_exploitable, abs=1e-9)
    assert out["host-a"]["juicy"]["true"] == pytest.approx(p_juicy, abs=1e-9)


def test_enablement_edge_contributes_as_an_additional_cause():
    """Two nodes: compromising A's `juicy` enables reaching B (ADR-0129) —
    an enablement cause on B's `reachable`, alongside B's own leak.
    """
    nodes = [
        NodeSpec(node_id="host-a", variables={"juicy": VariableSpec(leak=0.6)}),
        NodeSpec(node_id="host-b", variables={"reachable": VariableSpec(leak=0.1)}),
    ]
    enablement = [
        EnablementCause(
            source_node="host-a", source_variable="juicy",
            target_node="host-b", target_variable="reachable",
            strength=0.7,
        )
    ]
    out = solve_slice(nodes, enablement)

    p_a_juicy = 0.6
    p_b_given_a_true = 1.0 - (1.0 - 0.1) * (1.0 - 0.7)
    p_b_given_a_false = 1.0 - (1.0 - 0.1)
    want_b_reachable = p_a_juicy * p_b_given_a_true + (1 - p_a_juicy) * p_b_given_a_false

    assert out["host-a"]["juicy"]["true"] == pytest.approx(p_a_juicy, abs=1e-9)
    assert out["host-b"]["reachable"]["true"] == pytest.approx(want_b_reachable, abs=1e-9)
    # Without host-a's contribution, host-b would be at its bare leak (0.1) —
    # the enablement edge must have moved the posterior.
    assert out["host-b"]["reachable"]["true"] > 0.1


def test_dense_fan_in_stays_tractable():
    """A high-in-degree target (many upstream nodes all enabling one node)
    must ground to a bounded factor set, matching noisy_or's own tractability
    guarantee — this is the "stays O(parents)" acceptance criterion applied
    to a whole slice, not just one noisy_or_factors() call.
    """
    n = 30
    nodes = [NodeSpec(node_id=f"up-{i}", variables={"juicy": VariableSpec(leak=0.4)}) for i in range(n)]
    nodes.append(NodeSpec(node_id="target", variables={"reachable": VariableSpec(leak=0.05)}))
    enablement = [
        EnablementCause(
            source_node=f"up-{i}", source_variable="juicy",
            target_node="target", target_variable="reachable",
            strength=0.5,
        )
        for i in range(n)
    ]

    factors = ground_slice(nodes, enablement)
    assert len(factors) <= 4 * n + 4
    for f in factors:
        assert f.table.size <= 8

    out = solve_slice(nodes, enablement)
    assert 0.0 <= out["target"]["reachable"]["true"] <= 1.0
    assert out["target"]["reachable"]["true"] > 0.05  # moved off the bare leak


def test_evidence_pins_a_variable_and_propagates():
    nodes = [
        NodeSpec(
            node_id="host-a",
            variables={
                "reachable": VariableSpec(leak=0.3),
                "exploitable": VariableSpec(depends_on={"reachable": 0.9}, leak=0.0),
            },
        ),
    ]
    out = solve_slice(nodes, enablement=[], evidence={"host-a::reachable": "true"})
    assert out["host-a"]["reachable"]["true"] == 1.0
    # exploitable, conditioned on reachable=true, is exactly the noisy-OR
    # conditional (no leak contribution left to blend against a false state).
    assert out["host-a"]["exploitable"]["true"] == pytest.approx(0.9, abs=1e-9)


def test_deterministic_same_slice_same_posteriors():
    """The named acceptance criterion: identical slice -> identical posteriors."""

    def build():
        nodes = [
            NodeSpec(node_id="host-a", variables={"juicy": VariableSpec(leak=0.55)}),
            NodeSpec(
                node_id="host-b",
                variables={
                    "reachable": VariableSpec(leak=0.1),
                    "exploitable": VariableSpec(depends_on={"reachable": 0.8}, leak=0.02),
                },
            ),
        ]
        enablement = [
            EnablementCause(
                source_node="host-a", source_variable="juicy",
                target_node="host-b", target_variable="reachable",
                strength=0.65,
            )
        ]
        return nodes, enablement

    n1, e1 = build()
    n2, e2 = build()
    first = solve_slice(n1, e1)
    second = solve_slice(n2, e2)
    assert first == second


def test_a_node_can_appear_before_or_after_its_enablement_source_in_the_list():
    """Determinism must not depend on caller list order (a graph query gives
    no ordering guarantee)."""
    nodes_forward = [
        NodeSpec(node_id="host-a", variables={"juicy": VariableSpec(leak=0.5)}),
        NodeSpec(node_id="host-b", variables={"reachable": VariableSpec(leak=0.1)}),
    ]
    nodes_reversed = list(reversed(nodes_forward))
    enablement = [
        EnablementCause(
            source_node="host-a", source_variable="juicy",
            target_node="host-b", target_variable="reachable",
            strength=0.4,
        )
    ]
    a = solve_slice(nodes_forward, enablement)
    b = solve_slice(nodes_reversed, enablement)
    assert a == b
