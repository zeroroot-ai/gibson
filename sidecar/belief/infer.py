"""Exact variable elimination over a discrete Bayesian network (gibson#750, ADR-0005).

This is the inference engine the belief sidecar runs. It replaces pgmpy's
``VariableElimination`` with the same algorithm over plain numpy arrays.

Why it exists
-------------
``pgmpy==0.1.26`` requires ``torch``, and therefore also ``triton``,
``xgboost``, ``scikit-learn``, ``pandas``, ``scipy``, ``statsmodels`` and
``sympy`` — roughly 3 GB of a deep-learning stack, shipped into a production
image, to answer a marginal query over a seven-node binary network. Every one
of those packages is attack surface and CVE intake for a sidecar that does no
training, no autodiff and no tensor work (gibson#1436).

The algorithm here is not an approximation of what pgmpy did. Variable
elimination *is* exact inference: sum-product over the factor set in some
elimination order. The order changes the cost, never the answer. Parity against
``pgmpy==0.1.26`` is asserted directly in ``test_parity.py``, which is skipped
when pgmpy is absent (it is absent from the runtime image on purpose).

Determinism (ADR-0005 §replay)
------------------------------
Factors are built, multiplied and summed in a fixed, artifact-declared order:
variables keep the order the artifact lists them, and the elimination order is
derived deterministically from that. Identical inputs therefore produce
bit-identical float64 outputs on the same build, which is what replay needs.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

# Binary state labels, fixed so CPT column order is deterministic across
# artifacts. Kept in lockstep with model.STATES.
STATES: Tuple[str, ...] = ("false", "true")


class Factor:
    """A discrete factor: an ordered variable tuple plus a dense table.

    ``table`` has one axis per variable in ``variables``, in that order, and
    each axis has length 2 (every variable in a belief artifact is binary).
    """

    __slots__ = ("variables", "table")

    def __init__(self, variables: Sequence[str], table: np.ndarray):
        if len(variables) != table.ndim:
            raise ValueError(
                f"factor over {list(variables)} does not match a {table.ndim}-d table"
            )
        self.variables: Tuple[str, ...] = tuple(variables)
        self.table = table

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Factor({list(self.variables)}, shape={self.table.shape})"

    def reduce(self, evidence: Dict[str, str]) -> "Factor":
        """Return this factor conditioned on ``evidence``.

        Observed variables are sliced out of the table rather than summed, which
        is what makes the result a *conditional* rather than a marginal.
        """
        kept: List[str] = []
        index: List[object] = []
        for var in self.variables:
            state = evidence.get(var)
            if state is None:
                kept.append(var)
                index.append(slice(None))
            else:
                index.append(STATES.index(state))
        if len(kept) == len(self.variables):
            return self
        return Factor(kept, self.table[tuple(index)])

    def multiply(self, other: "Factor") -> "Factor":
        """Pointwise product over the union of both variable sets.

        Both tables are broadcast into the union's axis order, so this is a
        plain elementwise multiply with no einsum string to get wrong.
        """
        union: List[str] = list(self.variables)
        union.extend(v for v in other.variables if v not in self.variables)
        return Factor(union, _align(self, union) * _align(other, union))

    def sum_out(self, variable: str) -> "Factor":
        """Marginalise ``variable`` away."""
        axis = self.variables.index(variable)
        kept = self.variables[:axis] + self.variables[axis + 1 :]
        return Factor(kept, self.table.sum(axis=axis))


def _align(factor: Factor, union: Sequence[str]) -> np.ndarray:
    """Reshape ``factor``'s table so its axes line up with ``union`` for broadcast."""
    shape = [
        factor.table.shape[factor.variables.index(v)] if v in factor.variables else 1
        for v in union
    ]
    axes = [factor.variables.index(v) for v in union if v in factor.variables]
    return np.transpose(factor.table, axes).reshape(shape)


def cpd_to_factor(
    variable: str,
    values: Sequence[Sequence[float]],
    parents: Sequence[str] = (),
    parent_cards: Optional[Sequence[int]] = None,
) -> Factor:
    """Build a factor from an artifact CPD table.

    The on-disk layout is pgmpy's ``TabularCPD`` layout, kept unchanged so
    existing model artifacts load byte-for-byte as they did: a
    ``variable_card`` x ``prod(parent_cards)`` matrix whose columns enumerate
    the parent assignments in the declared parent order, **last parent varying
    fastest**. Reshaping to ``(variable_card, *parent_cards)`` is exactly that
    layout, which is why no transpose is needed here.
    """
    cards = list(parent_cards) if parent_cards else [len(STATES)] * len(parents)
    table = np.asarray(values, dtype=np.float64)
    expected = (len(STATES), int(np.prod(cards)) if cards else 1)
    if table.shape != expected:
        raise ValueError(
            f"cpd for {variable!r} has shape {table.shape}, expected {expected}"
        )
    return Factor([variable, *parents], table.reshape([len(STATES), *cards]))


def _elimination_order(
    factors: Sequence[Factor], keep: Iterable[str]
) -> List[str]:
    """Deterministic min-degree elimination order over everything not in ``keep``.

    Min-degree keeps intermediate factors small; ties break on the order the
    variable was first seen, so the order is a pure function of the artifact.
    Any order gives the same answer — this one just keeps the cost down.
    """
    keep_set = set(keep)
    seen: List[str] = []
    for factor in factors:
        for var in factor.variables:
            if var not in seen:
                seen.append(var)
    position = {var: i for i, var in enumerate(seen)}

    # Work on scopes only — never on tables. Simulating elimination with real
    # factors would allocate the intermediate tables twice, and on a wide
    # network the induced clique is exactly the array you cannot afford.
    scopes: List[frozenset] = [frozenset(f.variables) for f in factors]
    remaining = [v for v in seen if v not in keep_set]
    order: List[str] = []
    while remaining:
        degrees = {}
        for var in remaining:
            neighbours: set = set()
            for scope in scopes:
                if var in scope:
                    neighbours |= scope
            neighbours.discard(var)
            degrees[var] = len(neighbours)
        nxt = min(remaining, key=lambda v: (degrees[v], position[v]))
        order.append(nxt)
        remaining.remove(nxt)
        induced: set = set()
        for scope in scopes:
            if nxt in scope:
                induced |= scope
        scopes = [s for s in scopes if nxt not in s]
        induced.discard(nxt)
        if induced:
            scopes.append(frozenset(induced))
    return order


def query(
    factors: Sequence[Factor],
    variable: str,
    evidence: Optional[Dict[str, str]] = None,
) -> Dict[str, float]:
    """Exact P(``variable`` | ``evidence``) as a normalised state -> probability map.

    Raises ``ValueError`` if the evidence has zero probability under the model,
    rather than returning a silently-normalised nonsense distribution.
    """
    evidence = dict(evidence or {})
    evidence.pop(variable, None)

    reduced = [f.reduce(evidence) for f in factors]

    # A factor whose variables are all observed collapses to a scalar. That
    # scalar cancels in the normalisation and does not need carrying through
    # the elimination — but only if it is non-zero. A zero means the evidence
    # is impossible under the model, and dropping it there would hand back a
    # confidently normalised distribution over an event of probability zero.
    constant = 1.0
    working: List[Factor] = []
    for factor in reduced:
        if factor.variables:
            working.append(factor)
        else:
            constant *= float(factor.table)
    if constant == 0.0:
        raise ValueError(
            f"evidence {evidence!r} has zero probability under this model; "
            "P(variable | evidence) is undefined"
        )

    for var in _elimination_order(working, keep=[variable]):
        involved = [f for f in working if var in f.variables]
        if not involved:
            continue
        working = [f for f in working if var not in f.variables]
        product = involved[0]
        for factor in involved[1:]:
            product = product.multiply(factor)
        working.append(product.sum_out(var))

    result = working[0]
    for factor in working[1:]:
        result = result.multiply(factor)

    table = _align(result, [variable]).reshape(-1)
    total = float(table.sum())
    if not np.isfinite(total) or total <= 0.0:
        raise ValueError(
            f"evidence {evidence!r} has zero probability under this model; "
            "P(variable | evidence) is undefined"
        )
    normalised = table / total
    return {state: float(normalised[i]) for i, state in enumerate(STATES)}


def check_model(factors: Sequence[Factor], variables: Sequence[str]) -> None:
    """Validate the factor set the way pgmpy's ``check_model`` did.

    Every declared variable needs exactly one CPD, every parent referenced by a
    CPD must be declared, and each CPD must be a proper conditional
    distribution — its variable's states summing to 1 for every parent
    assignment.
    """
    declared = list(variables)
    owned = [f.variables[0] for f in factors]
    missing = [v for v in declared if v not in owned]
    if missing:
        raise ValueError(f"no cpd for declared variable(s): {missing}")
    extra = [v for v in owned if v not in declared]
    if extra:
        raise ValueError(f"cpd for undeclared variable(s): {extra}")
    if len(set(owned)) != len(owned):
        raise ValueError("more than one cpd declared for the same variable")

    for factor in factors:
        unknown = [v for v in factor.variables[1:] if v not in declared]
        if unknown:
            raise ValueError(
                f"cpd for {factor.variables[0]!r} names undeclared parent(s): {unknown}"
            )
        sums = factor.table.sum(axis=0)
        if not np.allclose(sums, 1.0, rtol=0.0, atol=1e-9):
            raise ValueError(
                f"cpd for {factor.variables[0]!r} is not normalised: "
                f"column sums {np.asarray(sums).reshape(-1).tolist()}"
            )

    # A cyclic parent relation is not a Bayesian network. Variable elimination
    # would still terminate on one and hand back a confident number, so reject
    # it here rather than serve a posterior that means nothing.
    parents = {f.variables[0]: set(f.variables[1:]) for f in factors}
    state: Dict[str, int] = {}  # 0 = visiting, 1 = done

    def visit(node: str, path: List[str]) -> None:
        mark = state.get(node)
        if mark == 1:
            return
        if mark == 0:
            cycle = path[path.index(node) :] + [node]
            raise ValueError(f"model is cyclic: {' -> '.join(cycle)}")
        state[node] = 0
        for parent in sorted(parents.get(node, ())):
            visit(parent, path + [node])
        state[node] = 1

    for node in declared:
        visit(node, [])
