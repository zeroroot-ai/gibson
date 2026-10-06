# gitlab plugin

A Gibson **plugin** (ADR-0065): a Go service that runs curated read/write logic
against the GitLab REST API through the maintained
[client-go](https://gitlab.com/gitlab-org/api/client-go) SDK (the successor to
go-gitlab).

It is Go-first — the method contracts are derived by the SDK from the typed Go
structs in `handler.go`, so there is no `.proto` and no generated code.

## Curated methods

| Method | Kind | GitLab call |
|--------|------|-------------|
| `GetProject` | read | `GET /projects/{id}` |
| `ListIssues` | read | `GET /projects/{id}/issues` |
| `CreateIssue` | write | `POST /projects/{id}/issues` |

A plugin exposes a stable, mission-shaped surface — a curated subset of the
vendor API — not the vendor's entire client.

## Credential

One GitLab personal or project access token resolved from the secrets broker,
declared in `plugin.yaml` as `cred:gitlab_token`. The broker is the only
credential channel — the plugin never reads a token from an env var, and never
puts it in a log line or an error.

## Test

```sh
go test ./...   # hermetic cassette replay — no daemon, no network, no token
```

`handler_test.go` replays committed `testdata/*.json` cassettes of the client-go
HTTP calls through a cassette-backed client, so the whole suite runs offline.

ADR-0065 is the contract of a plugin. The `gibson` release builds and signs the image, and the build writes its digest into the catalog (gibson#790).
