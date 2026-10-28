These files are real `output_json` values of the tool httpx. Each one was captured
from a digest-pinned gibson-executor image. The target was a local web server.

- `executor_v0.113.0_httpx_output.json`: image `sha256:9b22942410cb`, built on sdk v0.191.0.
  It holds fields that sdk v0.202.0 removed (`parent_type`, `content_length`).
- `executor_v0.114.0_httpx_output.json`: image `sha256:a22ea1e4101a`, built on sdk v0.202.0.

The test `TestExecute_DiscoveryFromExecutorOutput` reads both with the sdk of the daemon.
