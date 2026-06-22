"""Belief-field pgmpy sidecar HTTP server (gibson#750, ADR-0005).

Read-only exact inference over versioned model artifacts. Loads every
``models/*.json`` at startup and serves posteriors; it never trains.

    python -m server --models ./models --port 8087

Endpoints:
  POST /score   {version?, evidence, priors?} -> {version, juicy, exploitable, reachable, novel}
  GET  /healthz -> 200 "ok" once a model is loaded
  GET  /version -> {versions:[...], default:"..."}
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict

from model import BeliefModel, ModelArtifact


class Registry:
    """Loaded, versioned models. Read-only after startup."""

    def __init__(self) -> None:
        self.models: Dict[str, BeliefModel] = {}
        self.default: str = ""

    def load_dir(self, models_dir: str) -> None:
        paths = sorted(glob.glob(os.path.join(models_dir, "*.json")))
        for path in paths:
            artifact = ModelArtifact.load(path)
            self.models[artifact.version] = BeliefModel(artifact)
        # Deterministic default: lexicographically-greatest version (newest base-vN).
        if self.models:
            self.default = sorted(self.models)[-1]

    def get(self, version: str) -> BeliefModel:
        if version and version in self.models:
            return self.models[version]
        if not version and self.default:
            return self.models[self.default]
        raise KeyError(version or "<default>")


def make_handler(registry: Registry):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (stdlib name)
            if self.path == "/healthz":
                if registry.models:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                else:
                    self.send_response(503)
                    self.end_headers()
                return
            if self.path == "/version":
                self._json(200, {"versions": sorted(registry.models), "default": registry.default})
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/score":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                req = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid json"})
                return
            try:
                model = registry.get(req.get("version", ""))
            except KeyError as exc:
                self._json(404, {"error": f"unknown model version {exc}"})
                return
            try:
                out = model.score(req.get("evidence", {}), req.get("priors"))
            except Exception as exc:  # inference error -> 500, caller fails quiet
                self._json(500, {"error": str(exc)})
                return
            self._json(200, out)

        def log_message(self, *args) -> None:  # silence default stderr logging
            pass

    return Handler


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="belief-field pgmpy sidecar")
    parser.add_argument("--models", default=os.environ.get("BELIEF_MODELS_DIR", "./models"))
    parser.add_argument("--host", default=os.environ.get("BELIEF_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("BELIEF_PORT", "8087")))
    args = parser.parse_args(argv)

    registry = Registry()
    registry.load_dir(args.models)
    if not registry.models:
        print(f"no model artifacts in {args.models}", file=sys.stderr)
        return 1
    print(f"loaded {len(registry.models)} model(s); default={registry.default}", file=sys.stderr)

    server = ThreadingHTTPServer((args.host, args.port), make_handler(registry))
    print(f"belief sidecar listening on {args.host}:{args.port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
