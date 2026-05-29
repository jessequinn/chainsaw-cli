# v4-nuget-lockfile: .NET NuGet Lockfile Support

## Summary

Add a new `NugetScanner` that parses `packages.lock.json` for the
.NET/NuGet ecosystem.

## Motivation

.NET is dominant in enterprise environments -- exactly the audience
most affected by CRA obligations. NuGet lockfiles are JSON, making
parsing trivial.

## Design

New `NugetScanner` struct implementing `Scanner` interface:

- `Ecosystem()` returns new `EcosystemNuGet` constant.
- `DetectManifests()` walks for `packages.lock.json` files, skipping
  `bin/`, `obj/`, `.nuget/` directories.
- `ParseManifest()` parses the JSON structure:
  ```json
  {
    "version": 1,
    "dependencies": {
      "net8.0": {
        "PackageName": {
          "type": "Direct",
          "resolved": "1.0.0",
          "contentHash": "..."
        }
      }
    }
  }
  ```

Mark `type: "Direct"` as direct deps, `type: "Transitive"` as
indirect. Extract `contentHash` for integrity. OSV queries use
`NuGet` ecosystem.

## Non-goals

- `.csproj` / `.fsproj` PackageReference parsing (no lockfile).
- NuGet.config feed resolution.
- Framework-specific dependency filtering.

## Tasks

1. Add `EcosystemNuGet` constant to models -- ~5m
2. Create `internal/scanner/nuget.go` with JSON parser -- ~1h
3. Direct/transitive marking from `type` field -- ~15m
4. Test fixtures and tests -- ~1h
5. Update README ecosystem table -- ~10m

## Verification

- Parse `packages.lock.json` from popular .NET projects.
- Direct vs transitive counts match `dotnet list package`.
