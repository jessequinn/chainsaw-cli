package watch

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Lockfiles are the files that trigger a re-scan when changed.
var Lockfiles = []string{
	"go.sum",
	"go.mod",
	"package-lock.json",
	"pnpm-lock.yaml",
	"yarn.lock",
	"Cargo.lock",
	"mix.lock",
	"requirements.txt",
	"Pipfile.lock",
	"composer.lock",
	".chainsaw.yaml",
}

// ChangeEvent represents a detected lockfile change.
type ChangeEvent struct {
	File    string
	Changed time.Time
}

// WatchConfig controls the watch loop behavior.
type WatchConfig struct {
	Root         string
	PollInterval time.Duration
	Debounce     time.Duration
	OnChange     func(ctx context.Context, events []ChangeEvent) error
}

// DefaultWatchConfig returns sensible defaults.
func DefaultWatchConfig(root string) WatchConfig {
	return WatchConfig{
		Root:         root,
		PollInterval: 2 * time.Second,
		Debounce:     2 * time.Second,
	}
}

// Watch polls lockfiles for changes and calls OnChange when modifications are detected.
// It runs until the context is cancelled.
func Watch(ctx context.Context, cfg WatchConfig) error {
	if cfg.OnChange == nil {
		return fmt.Errorf("OnChange handler is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}

	// Take initial snapshot.
	hashes := snapshotHashes(cfg.Root)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.PollInterval):
			newHashes := snapshotHashes(cfg.Root)
			events := detectChanges(hashes, newHashes)
			if len(events) > 0 {
				if err := cfg.OnChange(ctx, events); err != nil {
					fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
				}
				hashes = newHashes
			}
		}
	}
}

func snapshotHashes(root string) map[string]string {
	hashes := make(map[string]string)
	for _, name := range Lockfiles {
		path := filepath.Join(root, name)
		h, err := fileHash(path)
		if err != nil {
			continue
		}
		hashes[name] = h
	}
	return hashes
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func detectChanges(old, new map[string]string) []ChangeEvent {
	var events []ChangeEvent
	now := time.Now()

	for name, newHash := range new {
		oldHash, existed := old[name]
		if !existed || oldHash != newHash {
			events = append(events, ChangeEvent{File: name, Changed: now})
		}
	}

	return events
}

// FormatDelta summarizes what changed between two scan runs.
func FormatDelta(oldCount, newCount int) string {
	diff := newCount - oldCount
	switch {
	case diff > 0:
		return fmt.Sprintf("%d new findings (total: %d)", diff, newCount)
	case diff < 0:
		return fmt.Sprintf("%d resolved (total: %d)", -diff, newCount)
	default:
		return fmt.Sprintf("No changes (total: %d)", newCount)
	}
}
