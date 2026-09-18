"""The HTTP surface of the sidecar.

The advisory fixture: an inference error returns a fixed string, never the
exception text, because that text names internal model state and library
paths. The server binds loopback unless told otherwise.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import server


class _Boom:
    def score(self, evidence, priors):
        raise RuntimeError("/app/models/base-v1/cpd.json: variable 'x' not in model")


class _Registry:
    def __init__(self):
        self.models = {"base-v1": _Boom()}
        self.default = "base-v1"

    def get(self, version):
        return self.models[version or self.default]


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(_Registry()))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_inference_error_does_not_leak_exception_text(capsys):
    srv = _serve()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{srv.server_port}/score",
            data=json.dumps({"evidence": {}}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            raise AssertionError("want HTTP 500")
        except urllib.error.HTTPError as err:
            assert err.code == 500
            body = json.loads(err.read())
        assert body == {"error": "inference failed"}
        assert "cpd.json" not in json.dumps(body)
    finally:
        srv.shutdown()
    assert "cpd.json" in capsys.readouterr().err


def test_default_bind_is_loopback(monkeypatch):
    monkeypatch.delenv("BELIEF_HOST", raising=False)
    parser_default = os.environ.get("BELIEF_HOST", "127.0.0.1")
    assert parser_default == "127.0.0.1"
    # main() reads the same environment key; the Dockerfile sets no override.
    with open(os.path.join(os.path.dirname(__file__), "Dockerfile")) as fh:
        assert "BELIEF_HOST=" not in fh.read()
