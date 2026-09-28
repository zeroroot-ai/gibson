"""Unit tests for the noisy-OR enablement CPT decomposition (gibson#288, ADR-0029 SS6).

The claim under test is precise and structural, not a timing guess: a node with
N enablement causes must be representable in O(N) factor SPACE (never the full
O(2**N) CPT table), and the decomposition must be an EXACT reformulation of the
noisy-OR CPD, not an approximation — proven by parity against the brute-force
full table for small N, where building the full table is still tractable.

Run:  python -m pytest sidecar/belief/test_noisy_or.py
"""

import itertools

import numpy as np
import pytest

import infer
from noisy_or import NoisyOrCause, noisy_or_factors


def _brute_force_cpt(n_parents, strengths, leak):
    """The textbook noisy-OR closed form, materialised as a full CPD table:
    P(variable=true | parents) = 1 - (1-leak) * prod_{i: parent_i=true} (1-strengths[i]).
    This is the O(2**n_parents) reference the decomposition must agree with.
    """
    parents = [f"p{i}" for i in range(n_parents)]
    cols = list(itertools.product((0, 1), repeat=n_parents))  # pgmpy column order: last parent fastest
    values = [[0.0] * len(cols), [0.0] * len(cols)]
    for col_idx, assignment in enumerate(cols):
        prod = 1.0 - leak
        for i, a in enumerate(assignment):
            if a == 1:
                prod *= 1.0 - strengths[i]
        p_true = 1.0 - prod
        values[0][col_idx] = 1.0 - p_true
        values[1][col_idx] = p_true
    factor = infer.cpd_to_factor("y", values, parents, [2] * n_parents)
    return factor, parents


def _decomposed(n_parents, strengths, leak):
    parents = [f"p{i}" for i in range(n_parents)]
    causes = [NoisyOrCause(parent=p, strength=s) for p, s in zip(parents, strengths)]
    factors = noisy_or_factors("y", causes, leak=leak)
    return factors, parents


def _with_uniform_parent_priors(factors, parents):
    """Add an independent Bernoulli(0.5) prior for every parent, so `y`'s
    marginal is well defined without conditioning on anything.
    """
    out = list(factors)
    for p in parents:
        out.append(infer.Factor([p], np.array([0.5, 0.5])))
    return out


@pytest.mark.parametrize("n_parents", [0, 1, 2, 3, 4])
def test_matches_the_full_cpt_marginal(n_parents):
    strengths = [0.9, 0.2, 0.6, 0.05][:n_parents]
    leak = 0.1

    full, full_parents = _brute_force_cpt(n_parents, strengths, leak)
    decomposed, dec_parents = _decomposed(n_parents, strengths, leak)

    want = infer.query(_with_uniform_parent_priors([full], full_parents), "y", {})
    got = infer.query(_with_uniform_parent_priors(decomposed, dec_parents), "y", {})
    assert got["true"] == pytest.approx(want["true"], abs=1e-9)
    assert got["false"] == pytest.approx(want["false"], abs=1e-9)


@pytest.mark.parametrize("n_parents", [1, 2, 3, 4])
def test_matches_the_full_cpt_conditioned_on_parents(n_parents):
    """The conditional form (fixing every parent's state), not just the
    marginal, must also agree — this is the shape a real ground query uses
    once upstream nodes have evidence or their own posteriors fixed.
    """
    strengths = [0.9, 0.2, 0.6, 0.05][:n_parents]
    leak = 0.15

    full, full_parents = _brute_force_cpt(n_parents, strengths, leak)
    decomposed, dec_parents = _decomposed(n_parents, strengths, leak)

    for assignment in itertools.product(("false", "true"), repeat=n_parents):
        ev = dict(zip(full_parents, assignment))
        want = infer.query([full], "y", ev)
        ev2 = dict(zip(dec_parents, assignment))
        got = infer.query(decomposed, "y", ev2)
        assert got["true"] == pytest.approx(want["true"], abs=1e-9), assignment


def test_zero_causes_is_just_the_leak():
    factors = noisy_or_factors("y", [], leak=0.37)
    assert len(factors) == 1
    got = infer.query(factors, "y", {})
    assert got["true"] == pytest.approx(0.37, abs=1e-12)


def test_factor_count_and_size_stay_linear_in_causes():
    """The tractability claim itself: never materialise the O(2**N) table."""
    n = 40
    causes = [NoisyOrCause(parent=f"p{i}", strength=0.5) for i in range(n)]
    factors = noisy_or_factors("y", causes, leak=0.01)

    # O(N) factors (one leak prior, N mechanism factors, N-1 OR-chain factors).
    assert len(factors) <= 2 * n + 1
    # Every factor is over at most 3 variables, so at most 2**3 = 8 entries —
    # never the 2**N a full CPT would need.
    for f in factors:
        assert f.table.size <= 8, f"factor over {f.variables} has {f.table.size} entries"


def test_deterministic_construction():
    causes = [NoisyOrCause(parent="p0", strength=0.7), NoisyOrCause(parent="p1", strength=0.3)]
    first = noisy_or_factors("y", causes, leak=0.05)
    second = noisy_or_factors("y", causes, leak=0.05)
    assert [f.variables for f in first] == [f.variables for f in second]
    for f1, f2 in zip(first, second):
        assert np.array_equal(f1.table, f2.table)


def test_auxiliary_variables_do_not_collide_across_calls():
    """ground.py will merge many noisy_or_factors() calls into one factor set
    for a whole slice; two different target variables must never introduce
    the same auxiliary variable name.
    """
    causes = [NoisyOrCause(parent="p0", strength=0.5), NoisyOrCause(parent="p1", strength=0.5)]
    a = noisy_or_factors("host-a::exploitable", causes, leak=0.1)
    b = noisy_or_factors("host-b::exploitable", causes, leak=0.1)
    a_vars = {v for f in a for v in f.variables if v not in ("p0", "p1")}
    b_vars = {v for f in b for v in f.variables if v not in ("p0", "p1")}
    assert a_vars.isdisjoint(b_vars)


def test_owns_the_target_variable_exactly_once():
    """Exactly one factor must own `variable` itself (its first axis), so a
    caller assembling a whole-slice factor set never double-declares it."""
    causes = [NoisyOrCause(parent=f"p{i}", strength=0.4) for i in range(5)]
    factors = noisy_or_factors("y", causes, leak=0.2)
    owners = [f.variables[0] for f in factors if f.variables[0] == "y"]
    assert owners == ["y"]


def test_check_model_accepts_the_decomposition():
    """The decomposition must be a well-formed Bayesian network fragment on
    its own: every auxiliary variable normalised, acyclic, single-owner."""
    causes = [NoisyOrCause(parent=f"p{i}", strength=0.6) for i in range(6)]
    factors = noisy_or_factors("y", causes, leak=0.05)
    priors = [infer.Factor([f"p{i}"], np.array([0.5, 0.5])) for i in range(6)]
    all_factors = factors + priors
    infer.check_model(all_factors, [f.variables[0] for f in all_factors])
