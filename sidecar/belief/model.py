"""Belief-field model artifacts and exact inference (gibson#750, ADR-0005).

A model artifact is a versioned JSON file describing a discrete Bayesian network:
binary variables, directed edges, and a CPT per variable. Inference is **exact**
(variable elimination, :mod:`infer`) and **read-only** — artifacts are loaded,
never trained online — so the belief field is deterministic and
replay-reproducible.

The pure functions here (``evidence_to_observations``, ``posteriors_from_marginals``)
carry no dependency at all; ``BeliefModel`` adds numpy and nothing else.
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
    """Exact-inference wrapper around a :class:`ModelArtifact`.

    Builds the factor set once at load time, then answers posteriors with
    variable elimination (exact — see :mod:`infer`). Read-only: no ``fit`` /
    structure learning is ever called at runtime.

    Inference used to run on ``pgmpy==0.1.26``. It no longer does. pgmpy pulls
    ``torch``, and with it ``triton``, ``xgboost``, ``scikit-learn``,
    ``pandas``, ``scipy``, ``statsmodels`` and ``sympy`` — an entire
    deep-learning stack shipped into production to marginalise a seven-node
    binary network (gibson#1436). ``infer.query`` runs the same algorithm on
    numpy alone; ``test_parity.py`` asserts agreement with pgmpy to 1e-12 and
    is skipped when pgmpy is absent, which it is in the runtime image.

    The on-disk CPD layout is unchanged — it is still pgmpy's ``TabularCPD``
    column layout — so existing model artifacts load untouched. That also means
    the pgmpy 0.1.26 / 1.0 ``BayesianNetwork`` vs ``DiscreteBayesianNetwork``
    rename that crashed the sidecar at startup (gibson#982 / deploy#826) can no
    longer happen: there is no pgmpy import left to break.
    """

    def __init__(self, artifact: ModelArtifact):
        # Imported here rather than at module scope so the pure helpers above
        # stay importable with no third-party dependency at all.
        import infer

        self.artifact = artifact
        self._factors = [
            infer.cpd_to_factor(
                var,
                spec["values"],
                spec.get("evidence", []),
                spec.get("evidence_card"),
            )
            for var, spec in artifact.cpds.items()
        ]
        infer.check_model(self._factors, artifact.variables)
        self._check_edges_match_cpds()
        self._infer = infer

    def _check_edges_match_cpds(self) -> None:
        """Reject an artifact whose ``edges`` disagree with its CPD parents.

        Inference reads parents off the CPDs, so ``edges`` is redundant — which
        is exactly why it has to be checked. pgmpy caught this because the graph
        and the CPDs were built from the two lists separately; nothing else
        would catch it now, and a stale ``edges`` list is the artifact bug most
        likely to go unnoticed.
        """
        from_edges: Dict[str, set] = {v: set() for v in self.artifact.variables}
        for parent, child in self.artifact.edges:
            if child not in from_edges:
                raise ValueError(f"edge names undeclared variable {child!r}")
            if parent not in from_edges:
                raise ValueError(f"edge names undeclared variable {parent!r}")
            from_edges[child].add(parent)

        for var, spec in self.artifact.cpds.items():
            declared = set(spec.get("evidence", []))
            if declared != from_edges.get(var, set()):
                raise ValueError(
                    f"model {self.artifact.version!r}: cpd for {var!r} lists parents "
                    f"{sorted(declared)} but edges give {sorted(from_edges.get(var, set()))}"
                )

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
            marginals[q] = self._infer.query(self._factors, q, ev)["true"]

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
