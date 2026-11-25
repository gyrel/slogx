# Agent instructions

## Scope

This repository provides structured logging helpers built on Go's
`log/slog`. Its module path is `github.com/gyrel/slogx` and its
license is MIT. The code derives from the owner-authorized `quarshell-slogx`
archive; see `NOTICE` for source attribution. The Go package name remains
`slogx`.

## Working rules

- Preserve the documented logging API and avoid exposing secrets or sensitive
  payload fields. Review masking behavior for nested and structured values.
- Do not describe masking as a guarantee. The README documents the limits of
  key-based rules, heuristic detection, fingerprints, payload helpers, and the
  unconfigured context fallback.
- Keep examples, README, and changelog in sync with exported API changes.
- Do not change the published module path or license as part of routine work.
  Keep the original copyright notice in `LICENSE`.

## Checks

- Run `GOWORK=off go test -race ./...` from this checkout for Go changes.
- Run `GOWORK=off go vet ./...`, `golangci-lint config verify`,
  `golangci-lint run ./...`, `govulncheck ./...`, and
  `GOWORK=off go mod tidy -diff`.
- Inspect the Makefile's lint and release checks before running them; the
  release scripts must not publish, tag, or push without explicit approval.
