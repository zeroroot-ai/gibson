"""Ground a bounded slice (gibson#287) into one exact-VE solvable network and
return per-node posteriors (gibson#288, ADR-0029 SS5).

A slice is a set of nodes, each with its own declared belief variables (the
ontology schema, gibson#296 — ``NodeSpec``/``VariableSpec`` mirror
``ontology.NodeBeliefSchema``/``BeliefVariable`` one level down, with the
DependsOn strengths and leaks a versioned model artifact supplies), plus the
enablement edges wiring one node's variable into another's (``EnablementCause``
— which target variable an edge feeds, and at what strength, is data the
caller supplies; this module makes no domain assumption about it).

``ground_slice`` treats every contributor to a variable — an intra-node
DependsOn parent and a cross-node enablement cause alike — as just another
independent noisy-OR cause of that variable (``noisy_or.py``): noisy-OR does
not distinguish "this node's own upstream variable" from "another node's
variable reached over an enablement edge", so ONE mechanism covers both the
per-node funnel ADR-0005 hardcoded (reachable -> exploitable -> juicy) and the
cross-node wiring ADR-0029 introduces. The result is one ground factor set;
``solve_slice`` runs ``infer.query`` (exact variable elimination, unchanged)
against it once per (node, variable) and returns every posterior.

Determinism: node/variable/cause iteration is always over an EXPLICITLY sorted
key, never raw input order or dict/set iteration, so the same slice grounds to
the same factor set (and the same posteriors) regardless of what order the
caller happened to list its nodes, variables or enablement causes in — the
same replay guarantee gibson#286/#287 give the graph derivation and slicing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

import infer
from noisy_or import NoisyOrCause, noisy_or_factors

SEPARATOR = "::"


def ground_name(node_id: str, variable: str) -> str:
    """The fully-qualified, ground factor-variable name for (node_id, variable)."""
    if SEPARATOR in node_id:
        raise ValueError(f"node id {node_id!r} must not contain {SEPARATOR!r}")
    if SEPARATOR in variable:
        raise ValueError(f"variable name {variable!r} must not contain {SEPARATOR!r}")
    return f"{node_id}{SEPARATOR}{variable}"


@dataclass(frozen=True)
class VariableSpec:
    """One node's declared belief variable (ontology.BeliefVariable, grounded):
    ``depends_on`` maps another variable NAME ON THE SAME NODE to the noisy-OR
    strength that variable contributes when true; ``leak`` is the background
    P(this variable=true) with every cause (intra-node and cross-node) absent.
    """

    depends_on: Dict[str, float] = field(default_factory=dict)
    leak: float = 0.0


@dataclass(frozen=True)
class NodeSpec:
    """One slice node (AttackGraphNode, grounded): its id and its own declared
    variables by name."""

    node_id: str
    variables: Dict[str, VariableSpec]


@dataclass(frozen=True)
class EnablementCause:
    """One enablement edge's contribution to a target variable: compromising
    (source_node, source_variable) is one more independent noisy-OR cause of
    (target_node, target_variable), at the given strength."""

    source_node: str
    source_variable: str
    target_node: str
    target_variable: str
    strength: float


def ground_slice(nodes: Sequence[NodeSpec], enablement: Sequence[EnablementCause]) -> List[infer.Factor]:
    """Build the whole-slice ground factor set: every node's own variables,
    each wired via noisy-OR to its intra-node DependsOn parents and any
    incoming enablement causes that target it.
    """
    by_target: Dict[tuple, List[EnablementCause]] = {}
    for c in enablement:
        by_target.setdefault((c.target_node, c.target_variable), []).append(c)
    for key, causes in by_target.items():
        # Stable, input-order-independent cause order.
        causes.sort(key=lambda c: (c.source_node, c.source_variable))

    factors: List[infer.Factor] = []
    for node in sorted(nodes, key=lambda n: n.node_id):
        for var_name in sorted(node.variables):
            spec = node.variables[var_name]
            gname = ground_name(node.node_id, var_name)

            causes = [
                NoisyOrCause(parent=ground_name(node.node_id, dep), strength=strength)
                for dep, strength in sorted(spec.depends_on.items())
            ]
            causes += [
                NoisyOrCause(parent=ground_name(c.source_node, c.source_variable), strength=c.strength)
                for c in by_target.get((node.node_id, var_name), [])
            ]
            factors.extend(noisy_or_factors(gname, causes, leak=spec.leak))

    return factors


def solve_slice(
    nodes: Sequence[NodeSpec],
    enablement: Sequence[EnablementCause],
    evidence: Optional[Dict[str, str]] = None,
) -> Dict[str, Dict[str, Dict[str, float]]]:
    """Ground the slice and return {node_id: {variable: {"true": p, "false": 1-p}}}
    for every declared variable, via exact variable elimination (never
    sampling — ADR-0005 SS2 still holds).

    ``evidence`` maps a ground name (``ground_name(node_id, variable)``) to an
    observed state ("true"/"false"); an observed variable reports probability
    1.0 for its observed state without needing a query.
    """
    factors = ground_slice(nodes, enablement)
    ev = dict(evidence or {})

    out: Dict[str, Dict[str, Dict[str, float]]] = {}
    for node in sorted(nodes, key=lambda n: n.node_id):
        out[node.node_id] = {}
        for var_name in sorted(node.variables):
            gname = ground_name(node.node_id, var_name)
            if gname in ev:
                observed = ev[gname]
                out[node.node_id][var_name] = {
                    "true": 1.0 if observed == "true" else 0.0,
                    "false": 1.0 if observed == "false" else 0.0,
                }
                continue
            q_ev = {k: v for k, v in ev.items() if k != gname}
            out[node.node_id][var_name] = infer.query(factors, gname, q_ev)

    return out
