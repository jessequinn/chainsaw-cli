# Change Proposal: v6-homebrew-formula

**Status:** Archived (implemented)
**Date:** 2026-05-29
**Author:** Agent

## Summary

Publish chainsaw as a Homebrew package via a dedicated tap
(`jessequinn/homebrew-chainsaw`), enabling one-line installation on
macOS and Linux. Add a GoReleaser configuration to produce versioned
release artifacts and wire it into the existing CI workflow. Establish a
clear path for eventual `homebrew-core` submission once the project
reaches the required adoption threshold.

## Motivation

chainsaw is a Go CLI distributed today only as a self-compiled binary.
The primary audience (developers, security engineers, CI pipelines) is
overwhelmingly on macOS and Linux where Homebrew is the de-facto package
manager. Without a tap, installation requires cloning the repo and
running `go build`, creating friction that reduces adoption. A tap also
enables:

- `brew upgrade chainsaw` for seamless version upgrades.
- Bottle caching (Homebrew CI pre-builds binaries), so users never need
  a Go toolchain.
- A clear path to `homebrew-core` once the project meets the admission
  threshold (>=90 GitHub stars/watchers/forks).

GoReleaser is added in the same change because Homebrew requires stable,
versioned source tarballs with a SHA-256 checksum and the project
currently has no automated release artifact pipeline.

## Proposed Changes

### 1. GoReleaser configuration (`.goreleaser.yml`)

Add a GoReleaser config at the repo root that:

- Builds cross-platform binaries for the five standard targets:
  `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`,
  `windows/amd64`.
- Injects the version via ldflags: `-X main.version={{.Version}}` (maps
  to the existing `var version = "dev"` in `cmd/chainsaw/main.go`).
- Produces a source tarball (`chainsaw-v{VERSION}-source.tar.gz`) in
  addition to binary archives -- required for the Homebrew formula URL.
- Generates a `checksums.txt` (SHA-256) alongside each artifact.
- Attaches a CycloneDX SBOM produced by Syft (pre-release checklist
  item already in AGENTS.md).
- Archives binary archives as `chainsaw_{VERSION}_{OS}_{ARCH}.tar.gz`.

Approximate `.goreleaser.yml` structure:

```yaml
version: 2

project_name: chainsaw

builds:
  - id: chainsaw
    main: ./cmd/chainsaw
    binary: chainsaw
    ldflags:
      - -s -w -X main.version={{.Version}}
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]
    ignore:
      - goos: windows
        goarch: arm64

archives:
  - id: default
    format: tar.gz
    format_overrides:
      - goos: windows
        format: zip
    name_template: "chainsaw_{{ .Version }}_{{ .Os }}_{{ .Arch }}"

source:
  enabled: true
  name_template: "chainsaw-{{ .Version }}-source"

checksum:
  name_template: "checksums.txt"
  algorithm: sha256

sboms:
  - artifacts: archive

release:
  github:
    owner: jessequinn
    name: chainsaw-cli
```

### 2. Custom Homebrew tap repository (`jessequinn/homebrew-chainsaw`)

Create a new public GitHub repository named `homebrew-chainsaw` under
the `jessequinn` organisation. This is a separate repository from the
main source; it holds only the Formula Ruby file. Users install via:

```
brew tap jessequinn/chainsaw
brew install chainsaw
```

Repository layout:

```
homebrew-chainsaw/
  Formula/
    chainsaw.rb
  README.md
```

### 3. Formula file (`Formula/chainsaw.rb`)

The formula builds chainsaw from the versioned source tarball produced
by GoReleaser. It declares Go as a build-time dependency, injects the
version via ldflags, installs the binary to `#{bin}`, generates shell
completions, and includes a functional test block.

```ruby
class Chainsaw < Formula
  desc "Supply chain security scanner for CRA compliance"
  homepage "https://github.com/jessequinn/chainsaw-cli"
  url "https://github.com/jessequinn/chainsaw-cli/releases/download/v#{version}/chainsaw-#{version}-source.tar.gz"
  version "0.3.3"
  sha256 "<sha256-of-source-tarball>"
  license "Apache-2.0"

  head "https://github.com/jessequinn/chainsaw-cli.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X main.version=#{version}
    ]
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/chainsaw"

    # Shell completions
    generate_completions_from_executable(bin/"chainsaw", "completion")
  end

  test do
    # Verify version string is embedded correctly
    assert_match version.to_s, shell_output("#{bin}/chainsaw version")

    # Verify scan help is reachable (no panic or missing subcommand)
    assert_match "scan", shell_output("#{bin}/chainsaw --help")

    # Verify scan of a minimal go.mod produces no crash (exit 0 = clean)
    (testpath/"go.mod").write <<~EOS
      module example.com/test

      go 1.21
    EOS
    system bin/"chainsaw", "scan", testpath.to_s
  end

  livecheck do
    url :stable
    strategy :github_latest
  end
end
```

Key notes:
- `std_go_args` is Homebrew's helper that passes the correct output
  path, disables cgo, and sets `GOFLAGS`.
- `generate_completions_from_executable` wires up `chainsaw completion
  bash/zsh/fish` automatically -- requires that the `completion`
  subcommand exists (Cobra generates it).
- `livecheck` with `:github_latest` tells Homebrew's `brew
  bump-formula-pr` automation to track the GitHub latest release.
- The `head` stanza lets maintainers test `brew install chainsaw --HEAD`
  without a release tag.

### 4. CI workflow update (`.github/workflows/release.yml`)

Add a release workflow that triggers on `v*` tag pushes and runs
GoReleaser:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - uses: goreleaser/goreleaser-action@v6
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

This replaces the manual release step in AGENTS.md's pre-release
checklist with an automated pipeline.

### 5. Tap formula auto-update

After each new GitHub Release, a Homebrew PR bot (or a simple GitHub
Actions workflow in `homebrew-chainsaw`) updates the `url`, `version`,
and `sha256` fields in `chainsaw.rb` automatically. The recommended
approach is a small workflow in `homebrew-chainsaw` that listens for
`repository_dispatch` events from the main repo's release workflow.

## Non-goals

- Submission to `homebrew-core` in this change. The project is pre-1.0
  and has not yet reached the >=90 star/watcher/fork threshold required
  by homebrew-core. A follow-up proposal will handle that once the
  threshold is met.
- Apt/RPM/Scoop/Chocolatey packages. Separate proposals per ecosystem.
- Docker image distribution.
- Automatic Homebrew cask for a GUI application (chainsaw is CLI-only).
- Adding `--self-update` to the binary (Homebrew forbids it; it was
  never planned anyway per AGENTS.md).
- Windows `winget` or `choco` formulae.

## Risks

- **License confirmed as Apache-2.0.** This is DFSG-compliant and
  accepted by homebrew-core. No blocker.
- **Go 1.26.3 is newer than what Homebrew's CI may have installed.**
  Homebrew CI uses the Go version in the formula's `depends_on`; if
  `go@1.26` is not yet available as a Homebrew formula, downgrade to
  the latest stable (1.24) and verify nothing breaks. Go 1.21+
  features used should be audited.
- **`completion` subcommand may not exist.** If Cobra's auto-generated
  `completion` command is not exposed, `generate_completions_from_executable`
  silently no-ops. Remove the call rather than let it fail.
- **Source tarball vs. VCS checkout.** Homebrew strongly prefers
  versioned tarballs over VCS checkouts for bottling. GoReleaser's
  `source.enabled: true` satisfies this.
- **SHA-256 must be recomputed for each release.** Formula PRs that
  forget to update the sha256 fail immediately in audit. The auto-update
  workflow in task 5 mitigates this.

## Acceptance Criteria

- `brew tap jessequinn/chainsaw && brew install chainsaw` completes
  successfully on macOS (arm64 and amd64) and Linux (x86_64).
- `brew test chainsaw` passes all three test assertions.
- `brew audit --strict chainsaw` produces zero errors.
- `chainsaw version` prints the correct version tag (not "dev").
- GoReleaser produces five binary archives, a source tarball, a
  `checksums.txt`, and a CycloneDX SBOM on tag push.
- Shell completions are installed and `source <(chainsaw completion
  zsh)` works in a fresh shell.
- `brew upgrade chainsaw` upgrades to the latest release without
  errors.
