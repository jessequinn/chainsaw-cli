# v4-cargo-lockfile: Rust Cargo.lock Support

## Summary

Add a new `RustScanner` that parses `Cargo.lock` for Rust/crates.io
ecosystem support.

## Motivation

Rust is increasingly used for CLI tools, infrastructure, and
security-critical software. CRA applies to Rust projects equally.
Cargo.lock is a well-structured TOML file, making it straightforward
to parse.

## Design

New `RustScanner` struct implementing `Scanner` interface:

- `Ecosystem()` returns new `EcosystemCratesIO` constant.
- `DetectManifests()` walks for `Cargo.lock` files, skipping
  `target/` directories.
- `ParseManifest()` parses TOML `[[package]]` entries. Each entry
  has `name`, `version`, `source`, and `checksum` fields.

Mark packages with `source = "registry+https://github.com/rust-lang/crates.io-index"`
as registry deps. Workspace members (no source field) are marked
as direct.

Requires adding `github.com/BurntSushi/toml` dependency (or
`github.com/pelletier/go-toml/v2`).

OSV queries use `crates.io` ecosystem.

## Non-goals

- Cargo workspace dependency resolution.
- Build script (`build.rs`) analysis.
- Feature flag evaluation.

## Tasks

1. Add `EcosystemCratesIO` constant to models -- ~5m
2. Create `internal/scanner/rust.go` with TOML parser -- ~1.5h
3. Add TOML dependency to `go.mod` -- ~5m
4. Test fixtures and tests -- ~1h
5. Update README ecosystem table -- ~10m

## Verification

- Parse Cargo.lock from ripgrep, tokio, serde.
- Vulnerability matches for known Rust CVEs.
