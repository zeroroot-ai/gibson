"""Noisy-OR enablement CPTs (gibson#288, ADR-0029 SS6).

A node with N independent enablement causes has a full CPD of 2**N columns —
intractable the moment N is more than a handful of parents, which an
enablement-edge fan-in reaches quickly. Noisy-OR is the standard compact
parameterisation for "any of several independent causes can each, on its own,
trigger the effect": P(variable=true | parents) = 1 - (1-leak) * prod over
true parents of (1 - strength_i). ``noisy_or_factors`` builds this CPD as an
O(N) DECOMPOSITION of small factors — never the O(2**N) table — by the
standard "parent divorcing" construction: one binary MECHANISM variable per
cause (active with probability `strength` exactly when its cause is true),
one LEAK mechanism (active with probability `leak` unconditionally, standing
in for the "true with no cause" background rate), and a chain of pairwise,
deterministic OR gates combining every mechanism into `variable`.

This is an EXACT reformulation, not an approximation: marginalising the
auxiliary mechanism/OR variables out of the decomposition (which
``infer.query``'s existing variable elimination already does for free — no
change to ``infer.py`` was needed) reproduces the noisy-OR closed form exactly.
``test_noisy_or.py`` proves this by parity against the brute-force full table
for small N, where building that table is still tractable to check against.

Every variable here is binary (``infer.STATES``), so noisy-OR is the complete
story; noisy-MAX (ADR-0029 SS6 names both) is noisy-OR's generalisation to
multi-valued variables, which nothing in this codebase has — STATES is fixed
at exactly two states everywhere the sidecar looks.

Naming: for a target `variable`, the auxiliary variables this function
introduces are named ``f"{variable}__leak"``, ``f"{variable}__z{i}"`` (the
i-th cause's mechanism) and ``f"{variable}__or{i}"`` (the i-th OR-chain
accumulator), so two calls for two different `variable`s can never collide —
see ``test_auxiliary_variables_do_not_collide_across_calls``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

import numpy as np

import infer


@dataclass(frozen=True)
class NoisyOrCause:
    """One independent cause in a noisy-OR CPD.

    ``parent`` is the GROUND (fully-qualified) name of the causing variable —
    noisy-OR does not care whether it is this node's own variable (an
    intra-node dependency) or another node's variable reached over an
    enablement edge (see ``ground.py``); both are just independent causes of
    the same effect. ``strength`` is P(variable=true caused by this parent
    alone, i.e. with every other cause and the leak both absent), in [0, 1].
    """

    parent: str
    strength: float


def noisy_or_factors(
    variable: str, causes: Sequence[NoisyOrCause], leak: float = 0.0
) -> List[infer.Factor]:
    """Build the O(len(causes)) noisy-OR decomposition for `variable`.

    Exactly one returned factor owns `variable` (its first axis) — the last
    OR-gate in the chain — so a caller merging this into a larger factor set
    (``ground.py``) can treat the return value as "the CPD for variable" the
    same way it would treat a single `infer.cpd_to_factor` result.
    """
    if not 0.0 <= leak <= 1.0:
        raise ValueError(f"leak must be in [0, 1], got {leak!r}")
    for c in causes:
        if not 0.0 <= c.strength <= 1.0:
            raise ValueError(f"cause {c.parent!r} strength must be in [0, 1], got {c.strength!r}")

    leak_var = f"{variable}__leak"
    if not causes:
        # No causes at all: variable is just the leak's Bernoulli prior —
        # naming it `variable` directly rather than `leak_var` keeps the
        # zero-cause case a single, ordinary prior factor.
        return [infer.Factor([variable], np.array([1.0 - leak, leak]))]

    factors: List[infer.Factor] = [infer.Factor([leak_var], np.array([1.0 - leak, leak]))]

    mechanisms = []
    for i, cause in enumerate(causes):
        z = f"{variable}__z{i}"
        mechanisms.append(z)
        # table[z_state][parent_state]: the mechanism can only fire when its
        # cause is true, and then fires with probability `strength`.
        table = np.array([[1.0, 1.0 - cause.strength], [0.0, cause.strength]])
        factors.append(infer.Factor([z, cause.parent], table))

    # Deterministic pairwise OR chain: acc_0 = leak_var; acc_i = OR(acc_{i-1}, z_i).
    # The final accumulator IS `variable` itself.
    or_table = np.zeros((2, 2, 2))
    for a in (0, 1):
        for b in (0, 1):
            or_table[1 if (a or b) else 0, a, b] = 1.0

    acc = leak_var
    for i, z in enumerate(mechanisms):
        is_last = i == len(mechanisms) - 1
        out = variable if is_last else f"{variable}__or{i}"
        factors.append(infer.Factor([out, acc, z], or_table))
        acc = out

    return factors
