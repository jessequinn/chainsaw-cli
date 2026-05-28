# Change Proposal: v2-elixir

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Summary

Add Elixir/Erlang ecosystem scanning to chainsaw. Parse `mix.lock` to
enumerate Hex dependencies and query OSV for known vulnerabilities.

## Motivation

Elixir is widely used in telecom, fintech, and real-time systems — all
sectors with CRA exposure. The Hex package manager has a single lockfile
format (`mix.lock`) that is well-structured and stable. This makes it a
low-effort, high-value addition.

## Proposed Changes

### New Ecosystem Constant

Add `EcosystemHex Ecosystem = "hex"` to `pkg/models/models.go`.

### New Scanner: `internal/scanner/elixir.go`

Implement `ElixirScanner` satisfying the `Scanner` interface.

**DetectManifests** finds `mix.lock` files. Skip `_build/`, `deps/`,
`.elixir_ls/` directories.

**ParseDependencies** parses the `mix.lock` Elixir term format:

```elixir
%{
  "phoenix": {:hex, :phoenix, "1.7.10", "02189140a61b2ce85bb633a9b6fd02dfa645...", ...},
  "plug": {:hex, :plug, "1.15.2", "abc123...", ...},
  "ecto": {:git, "https://github.com/elixir-ecto/ecto.git", "abc123...", ...},
}
```

Each line in the map follows a predictable pattern:
- Hex packages: `"name": {:hex, :name, "version", "hash", ...}`
- Git packages: `"name": {:git, "url", "ref", ...}`

The parser should:
1. Read `mix.lock` as text
2. For each line matching the hex tuple pattern, extract name, version,
   and SHA-256 hash (the 4th element)
3. Skip git-sourced dependencies (no version in registry)
4. Construct purl: `pkg:hex/package-name@version`

This is a regex/text-based parser — no Elixir AST parsing needed. The
format is stable and machine-readable despite being Elixir syntax.

### OSV Ecosystem Mapping

Map `"hex"` to `"Hex"` in `internal/vuln/client.go` `mapEcosystem()`.

### Typosquatting List

Add top 20 popular Hex packages to `internal/hygiene/typosquat.go`:
`phoenix`, `ecto`, `plug`, `phoenix_html`, `phoenix_live_view`,
`jason`, `telemetry`, `phoenix_pubsub`, `swoosh`, `bamboo`,
`ex_machina`, `credo`, `dialyxir`, `absinthe`, `guardian`,
`httpoison`, `tesla`, `oban`, `broadway`, `nx`.

## Non-goals

- Parsing `mix.exs` dependency declarations (build manifest, not lockfile)
- Erlang `rebar.lock` support (separate proposal if needed)
- Resolving git-sourced dependencies against Hex

## Risks

- `mix.lock` is Elixir syntax, not a standard format (JSON/TOML/YAML).
  Mitigation: the format is highly regular and has been stable since
  Elixir 1.0. Regex-based parsing is sufficient and avoids needing an
  Elixir parser.
- Hex ecosystem is smaller, so OSV coverage may be limited. This is
  acceptable — scanning still catches what exists.

## Acceptance Criteria

- `chainsaw scan --ecosystem hex .` detects Elixir dependencies
- Parses `mix.lock` hex tuples correctly
- Skips git-sourced dependencies gracefully
- Components have correct purls (`pkg:hex/...`)
- OSV queries use `"Hex"` ecosystem
- Unit tests with fixture `mix.lock` files

## Tasks

- [ ] Add `EcosystemHex` constant to `pkg/models/models.go`
- [ ] Implement `ElixirScanner` in `internal/scanner/elixir.go`
- [ ] Regex-based `mix.lock` parser for hex tuples
- [ ] Add `"hex"` -> `"Hex"` mapping in `internal/vuln/client.go`
- [ ] Add popular Hex packages to typosquatting list
- [ ] Unit tests with fixture `mix.lock` in `testdata/elixir/`
