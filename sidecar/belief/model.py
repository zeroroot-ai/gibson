"""Belief-field model artifacts and exact inference (gibson#750, ADR-0005).

A model artifact is a versioned JSON file describing a discrete Bayesian network:
binary variables, directed edges, and a CPT per variable. Inference is **exact**
(pgmpy ``VariableElimination``) and **read-only** — artifacts are loaded, never
trained online — so the belief field is deterministic and replay-reproducible.

The pure functions here (``evidence_to_observations``, ``posteriors_from_marginals``)
carry no pgmpy dependency so they are unit-testable without the heavy stack; the
``BeliefModel`` adapter wraps pgmpy and is exercised when the lib is installed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# The three belief-field components every model MUST expose (ADR-0005).
QUERY_VARS: Tuple[str, ...] = ("juicy", "exploitable", "reachable")

# Binary state labels, fixed so CPT column order is deterministic across artifacts.
STATES: Tuple[str, ...] = ("false", "true")


def evidence_to_observations(evidence: dict, known_vars: set) -> Tuple[Dict[str, str], List[str]]:
    """Map host evidence onto observed network variables.

    Returns ``(observations, novel)`` where ``observations`` maps a known network
    variable to its observed state ("true"/"false"), and ``novel`` lists evidence
    tokens the network has no variable for (ADR-0005 §6: the caller's LLM fills
    these, the math does not guess). Deterministic: identical evidence yields
    identical observations, so exact inference is reproducible.

    Evidence variables follow stable conventions:
      - ``reachable`` ← evidence["reachable"]
      - ``port_<n>``  ← n in evidence["open_ports"]
      - ``svc_<name>``← "<port>/<name>" in evidence["services"]
    Only variables the network declares are set; the rest are flagged novel.
    """
    obs: Dict[str, str] = {}
    novel: List[str] = []

    if "reachable" in known_vars:
        obs["reachable"] = "true" if evidence.get("reachable") else "false"

    for port in sorted(evidence.get("open_ports", [])):
        var = f"port_{port}"
        if var in known_vars:
            obs[var] = "true"
        else:
            novel.append(var)

    for svc in sorted(evidence.get("services", [])):
        # "<port>/<name>" -> svc_<name>
        name = svc.split("/", 1)[1] if "/" in svc else svc
        var = f"svc_{name}"
        if var in known_vars:
            obs[var] = "true"
        else:
            novel.append(var)

    return obs, novel


def posteriors_from_marginals(marginals: Dict[str, float]) -> Dict[str, float]:
    """Pull the three belief-field components out of per-variable P(true) marginals.

    Missing query vars default to 0.0 (an unscored component, not a guess).
    """
    return {v: float(marginals.get(v, 0.0)) for v in QUERY_VARS}


@dataclass
class ModelArtifact:
    """A parsed, versioned model artifact (the on-disk JSON)."""

    version: str
    variables: List[str]
    edges: List[Tuple[str, str]]
    cpds: Dict[str, dict]
    raw: dict = field(default_factory=dict)

    @property
    def known_vars(self) -> set:
        return set(self.variables)

    @classmethod
    def load(cls, path: str) -> "ModelArtifact":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict) -> "ModelArtifact":
        version = raw["version"]
        variables = list(raw["variables"])
        edges = [tuple(e) for e in raw.get("edges", [])]
        cpds = raw["cpds"]
        for q in QUERY_VARS:
            if q not in variables:
                raise ValueError(f"model {version!r} missing required query var {q!r}")
        return cls(version=version, variables=variables, edges=edges, cpds=cpds, raw=raw)


class BeliefModel:
    """pgmpy-backed exact-inference wrapper around a :class:`ModelArtifact`.

    Builds a ``DiscreteBayesianNetwork`` once at load time, then answers posteriors
    with ``VariableElimination`` (exact). Read-only: no ``fit`` / structure learning
    is ever called at runtime.
    """

    def __init__(self, artifact: ModelArtifact):
        # Imported lazily so the pure helpers above stay importable without pgmpy.
        from pgmpy.models import DiscreteBayesianNetwork
        from pgmpy.factors.discrete import TabularCPD
        from pgmpy.inference import VariableElimination

        self.artifact = artifact
        net = DiscreteBayesianNetwork(artifact.edges)
        net.add_nodes_from(artifact.variables)

        for var, spec in artifact.cpds.items():
            parents = spec.get("evidence", [])
            parent_card = spec.get("evidence_card", [2] * len(parents))
            cpd = TabularCPD(
                variable=var,
                variable_card=2,
                values=spec["values"],
                evidence=parents or None,
                evidence_card=parent_card or None,
                state_names={n: list(STATES) for n in [var, *parents]},
            )
            net.add_cpds(cpd)

        net.check_model()
        self._infer = VariableElimination(net)

    @property
    def version(self) -> str:
        return self.artifact.version

    def score(self, evidence: dict, priors: Optional[Dict[str, dict]] = None) -> dict:
        """Run exact inference and return the three components plus any novel vars.

        ``priors`` (optional) supplies caller-estimated priors for novel nodes
        (ADR-0005 §6). They are applied as virtual evidence on the query vars when
        the network truly has no table — here they directly seed the response for
        a missing component, keeping the call bounded and deterministic.
        """
        obs, novel = evidence_to_observations(evidence, self.artifact.known_vars)

        marginals: Dict[str, float] = {}
        for q in QUERY_VARS:
            # A query var that is itself directly observed (e.g. reachable) takes
            # its observed value, not a marginalized prior — the evidence is the
            # answer. Otherwise condition on the rest of the evidence and infer.
            if q in obs:
                marginals[q] = 1.0 if obs[q] == "true" else 0.0
                continue
            ev = {k: v for k, v in obs.items() if k != q}
            result = self._infer.query(variables=[q], evidence=ev, show_progress=False)
            marginals[q] = float(result.get_value(**{q: "true"}))

        out = posteriors_from_marginals(marginals)

        # If the caller supplied a prior for a still-novel component, honor it.
        if priors:
            merged = next(iter(priors.values())) if priors else {}
            for q in QUERY_VARS:
                if q in merged and out.get(q, 0.0) == 0.0:
                    out[q] = float(merged[q])

        out["version"] = self.version
        out["novel"] = [{"reason": f"unknown variable: {n}"} for n in novel]
        return out
