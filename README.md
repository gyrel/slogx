# slogx

Structured logging helpers for Rheic components, built on Go's
[`log/slog`](https://pkg.go.dev/log/slog). The Go package name is `slogx`; the module
path is `github.com/rheic/slogx`.

[![CI](https://github.com/rheic/slogx/actions/workflows/ci.yml/badge.svg)](https://github.com/rheic/slogx/actions/workflows/ci.yml)
[![Go 1.27.4+](https://img.shields.io/badge/Go-1.27.4+-blue)](https://go.dev/dl/)

> Status: alpha. This repository has no published release yet. Treat masking as
> defense in depth, not as a guarantee that secrets cannot reach logs. See
> [Security limits](#security-limits).

## Features

- **Runtime configuration** — change level, format (JSON/Text), masking, and removal without restart
- **Live level control** — `SetLevel` / env watch (`LOG_LEVEL`)
- **Field masking** — configurable key rules plus limited heuristic detection for common secret shapes; see the limits below
- **OpenTelemetry** — automatic `trace_id`, `span_id`, and `trace_sampled` from `context.Context`
- **Stack traces** — optional stack attachment on `Error` and `Fatal` records
- **Typed context keys** — collision-safe `ContextKey`; logger in context via `ToContext` / `FromContext`
- **Bounded dumping** — struct serialization via saferefl (depth limits, cycles, field caps)
- **Payload helpers** — HTTP and gRPC snapshots with sensitive headers and metadata filtered

## Install

The module path is `github.com/rheic/slogx`. No tagged release exists yet,
so external `go get` is not supported until the first release. Inside the Rheic
workspace, use the sibling checkout and pin a tag once one is published:

```bash
go get github.com/rheic/slogx@<tag>
```

For local development run checks with the module's own dependency graph:

```bash
GOWORK=off go test -race ./...
```

## Quick start

```go
package main

import (
    "context"
    "log/slog"

    "github.com/rheic/slogx"
)

func main() {
    log := slogx.New(
        slogx.WithFormat(slogx.FormatJSON),
        slogx.WithTraceContext(true),
        slogx.WithStackOnError(true),
        slogx.WithContextKeys(slogx.KeyRequestID),
        slogx.WithMaskRules(
            slogx.NewMaskRules().Add("email", slogx.MaskEmail),
        ),
    )
    slog.SetDefault(log.Logger)

    ctx := slogx.WithValue(context.Background(), slogx.KeyRequestID, "req-1")
    log.InfoContext(ctx, "started", slog.String("email", "user@example.com"))
}
```

## Presets

```go
log := slogx.Default()    // JSON, Info, OTel, stack, corporate field rules
log := slogx.Dev()        // Text, Debug, OTel, stack, corporate field rules
log := slogx.Corporate()  // alias of Default()
log := slogx.New(slogx.WithCorporateMasking())
```

## Live log level

```go
log.SetLevelString("debug")
go log.WatchLevelEnv(ctx, "LOG_LEVEL", 0) // poll env
```

## Examples

Runnable examples live under [`examples/`](examples/):

| Example | What it shows |
| --- | --- |
| [`examples/basic/`](examples/basic/) | levels, formats, `Err`, `NewNop` |
| [`examples/masking/`](examples/masking/) | key-based masking and removal |
| [`examples/context/`](examples/context/) | typed context keys, `ToContext` / `FromContext` |
| [`examples/tracing/`](examples/tracing/) | OpenTelemetry `trace_id` / `span_id` injection |
| [`examples/stack/`](examples/stack/) | `AddSource`, stack on Error/Fatal, `WithExitFunc` |
| [`examples/dump/`](examples/dump/) | `Dump` / `DumpGroup` via saferefl |
| [`examples/http_payload/`](examples/http_payload/) | HTTP request/response snapshots |
| [`examples/grpc_payload/`](examples/grpc_payload/) | gRPC call/response/stream snapshots |
| [`examples/runtime_config/`](examples/runtime_config/) | `UpdateConfig` / `SetLevel` hot reload |
| [`examples/level_control/`](examples/level_control/) | runtime log-level updates |
| [`examples/presets/`](examples/presets/) | `Default`, `Dev`, `MustDefault` |

```bash
GOWORK=off go run ./examples/basic/
GOWORK=off go run ./examples/tracing/
GOWORK=off go run ./examples/dump/
make examples
```

## Dumping

```go
log.Info("payload",
    slogx.DumpWith(log, "user", user),
)
```

`Dump` walks exported struct fields and map entries, applies the logger's key rules,
and enforces depth and field limits. Values passed directly as `slog.Any` are not
walked by the handler; use `DumpWith` when nested traversal is required.

## HTTP / gRPC payloads

```go
log.Info("http", slogx.HTTPRequestWith(log, "request", req))
log.Info("grpc", slogx.GRPCCallWith(log, "call", "/svc.Method", body, md))
```

A fixed set of sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`,
`X-Api-Key`, `X-Auth-Token`, `Proxy-Authorization`) and their gRPC metadata
equivalents is replaced with `[SECRET]`; configured key rules are also applied.

Payload values are summarized, not logged. HTTP bodies produce `body_bytes` and
`body_sha256` for the inspected prefix plus `body_truncated` when the limit is
exceeded; the full body is restored for downstream readers. URLs are logged without
userinfo, query values, or fragments, and `url_query_redacted` marks a stripped
query. gRPC request, response, and stream values produce `<kind>_type`,
`<kind>_bytes`, and `<kind>_sha256` from their bounded, masked serialization. Raw
bodies and payload values never reach the log record. Use `WithDumpBodyLimit` to
bound inspection; the default is 16 KiB. See [Security limits](#security-limits).

## Runtime config

```go
log.UpdateConfig(func(c *slogx.Config) {
    c.Level = slog.LevelDebug
    c.Format = slogx.FormatJSON
})
```

## Security limits

Masking is best-effort defense in depth. It is not a data-loss-prevention system and
does not guarantee that credentials, personal data, or sensitive payloads are absent
from logs.

- **Masking is key-based.** Only attributes whose names match configured rules (or
  nested group paths) are masked. A secret stored under an unregistered key is logged
  as-is. Direct `slog.Any` maps and structs are not traversed by the handler; use
  `DumpWith` for bounded traversal.
- **Heuristic detection is narrow.** Corporate mode recognizes a few string shapes:
  JWTs with a base64url JSON header, AWS access key IDs, PEM private-key headers,
  `Bearer` prefixes, IBAN-shaped strings, and Luhn-valid PANs. It is not generic
  entropy detection and does not recognize arbitrary API keys, passwords, or
  connection strings.
- **Partial masking reveals data.** Email masking keeps the domain and the first
  local-part characters; phone masking keeps the first and last three digits; card
  masking keeps the BIN and last four digits; IBAN masking keeps the country/check
  prefix and last four characters; JWT masking keeps header and signature fragments.
- **Fingerprints are unsalted.** `MaskHash` and fingerprinting use SHA-256 without a
  secret key. They support correlation, but low-entropy secrets can be brute-forced
  offline. Fingerprinting is opt-in.
- **Errors and paths are raw.** `Err` logs the error string unchanged, and
  `AddSource`/stack traces include file paths. Error text frequently contains
  endpoints, queries, or user data, so callers must sanitize before logging.
- **Payload helpers are metadata-only.** HTTP bodies and gRPC payload values are
  never written to the log; only type, size, and SHA-256 fields are recorded, so
  correlation does not reveal content. HTTP paths remain in the logged URL and may
  carry secret-shaped segments; query values, userinfo, and fragments are removed.
  gRPC metadata is filtered by key rules and the fixed header list; it does not run
  corporate value auto-detection. Body digests cover the inspected prefix when
  `body_truncated` is true. Downstream readers receive the complete body.
- **Removal is exact-key based.** `RemovalSet` entries match the normalized full key
  or the leaf attribute name. Nested map and struct values are only inspected by
  `Dump`, not by the handler.
- **Context fallback is unconfigured.** `FromContext` without an injected logger or a
  `SetupDefault`/`MustDefault` handler returns a wrapper around `slog.Default()`.
  That fallback does not install masking. `FatalContext` still follows its documented
  exit contract: the fallback uses the `WithExitFunc` hook when the default handler was
  installed with it, otherwise it calls `os.Exit(1)`.
- **Audit text redaction is heuristic.** `RedactAuditText` rewrites query strings and
  common inline credential patterns; unrecognized secret formats remain.

Callers remain responsible for not logging secrets, tokens, credentials, raw
requests, or personal data.

## Development

```bash
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
GOWORK=off go mod tidy -diff
golangci-lint config verify
golangci-lint run ./...
govulncheck ./...
make coverage
make lint
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md).

## Source attribution

This repository was imported from the owner-authorized MIT-licensed
`quarshell-slogx` sources in the `rheic/quarshell` archive at
`archive-sources/quarshell-slogx`, commit
`ac476dcc0e89b4efc9c3b2b484054026d9d32275`. The original copyright notice is retained
in [LICENSE](LICENSE) and [NOTICE](NOTICE). Changes in this repository are limited to
the module path, Go version, imports, documentation, CI, validation, the internal
stack-frame filter path, and the `FromContext` fallback exit contract; masking and
logging semantics are otherwise unchanged.

## License

MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
