# v5-watch-mode: Continuous Scanning Watch Mode

## Summary

Add `chainsaw watch [path]` command. Uses fsnotify to watch lockfiles (go.sum, package-lock.json, pnpm-lock.yaml, etc.). On change: debounce 2s, re-run scan, display delta (new/resolved findings). Ctrl+C to exit. Useful during `go get` or `npm install` sessions for real-time feedback.

## Motivation

Developers need real-time feedback while updating dependencies. Watch mode provides instant scanning without manual command invocation, improving workflow efficiency.

## Design

New command `internal/cmd/watch.go`:
- Use `github.com/fsnotify/fsnotify` for file watching
- Watch lockfiles and policy file
- Debounce events (2s) to avoid redundant scans
- On trigger: run scan, compare with previous result
- Display delta: "2 new, 1 resolved" with brief summary
- Handle errors gracefully (e.g., invalid lockfile)
- Ctrl+C exits cleanly

## Non-goals

- Live log streaming
- Metrics/performance tracing
- Watch-mode configuration file

## Tasks

1. Add fsnotify dependency to go.mod -- ~15m
2. Implement watch command skeleton -- ~45m
3. Implement file watcher with debouncing -- ~1.5h
4. Implement scan delta calculation -- ~1h
5. Add clear/readable output formatting -- ~45m
6. Add integration tests (mock fsnotify) -- ~1.5h

## Verification

- File changes trigger re-scan
- Debouncing prevents redundant scans on rapid changes
- Delta output clear and accurate
- Ctrl+C exits gracefully
- Error handling (invalid files, parse errors)
- Works with all supported ecosystems
- Performance acceptable (no lag on scan)
