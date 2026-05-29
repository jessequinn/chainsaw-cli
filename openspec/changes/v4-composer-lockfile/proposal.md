# v4-composer-lockfile: PHP Composer Lockfile Support

## Summary

Add a new `ComposerScanner` that parses `composer.lock` for the
PHP/Packagist ecosystem.

## Motivation

PHP powers a large share of web applications. Composer lockfiles are
JSON with a clean structure. Many PHP projects fall under CRA scope
(e-commerce, payment processing).

## Design

New `ComposerScanner` struct implementing `Scanner` interface:

- `Ecosystem()` returns new `EcosystemPackagist` constant.
- `DetectManifests()` walks for `composer.lock` files, skipping
  `vendor/` directories.
- `ParseManifest()` parses JSON arrays `packages` (production) and
  `packages-dev` (development):
  ```json
  {
    "packages": [
      {
        "name": "vendor/package",
        "version": "v1.0.0",
        "dist": { "type": "zip", "shasum": "..." }
      }
    ],
    "packages-dev": [...]
  }
  ```

Mark `packages` as direct, `packages-dev` as dev dependencies
(still scanned but flagged). Strip leading `v` from version for
OSV queries. Use `Packagist` ecosystem for OSV.

## Non-goals

- `composer.json` constraint resolution (lockfile only).
- Platform requirements (`php`, `ext-*`).
- Plugin/script analysis.

## Tasks

1. Add `EcosystemPackagist` constant to models -- ~5m
2. Create `internal/scanner/composer.go` with JSON parser -- ~1h
3. Dev dependency flagging -- ~15m
4. Test fixtures and tests -- ~1h
5. Update README ecosystem table -- ~10m

## Verification

- Parse `composer.lock` from Laravel, Symfony, WordPress.
- Vulnerability matches for known PHP CVEs.
