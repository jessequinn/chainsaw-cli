package watch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotHashes_detects_existing(t *testing.T) {
	dir := t.TempDir()
	gosum := filepath.Join(dir, "go.sum")
	if err := os.WriteFile(gosum, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	hashes := snapshotHashes(dir)
	if hash, ok := hashes["go.sum"]; !ok || hash == "" {
		t.Errorf("expected go.sum hash, got: %v", hashes)
	}
}

func TestSnapshotHashes_skips_missing(t *testing.T) {
	dir := t.TempDir()
	hashes := snapshotHashes(dir)
	if len(hashes) != 0 {
		t.Errorf("expected empty map for empty dir, got: %v", hashes)
	}
}

func TestDetectChanges_new_file(t *testing.T) {
	old := make(map[string]string)
	new := map[string]string{"go.sum": "abc123"}

	events := detectChanges(old, new)
	if len(events) != 1 || events[0].File != "go.sum" {
		t.Errorf("expected 1 event for go.sum, got: %v", events)
	}
}

func TestDetectChanges_changed_file(t *testing.T) {
	old := map[string]string{"go.sum": "hash1"}
	new := map[string]string{"go.sum": "hash2"}

	events := detectChanges(old, new)
	if len(events) != 1 || events[0].File != "go.sum" {
		t.Errorf("expected 1 event for changed go.sum, got: %v", events)
	}
}

func TestDetectChanges_no_change(t *testing.T) {
	old := map[string]string{"go.sum": "hash1"}
	new := map[string]string{"go.sum": "hash1"}

	events := detectChanges(old, new)
	if len(events) != 0 {
		t.Errorf("expected no events for unchanged file, got: %v", events)
	}
}

func TestFormatDelta_new_findings(t *testing.T) {
	result := FormatDelta(3, 5)
	if result != "2 new findings (total: 5)" {
		t.Errorf("expected '2 new findings (total: 5)', got: %s", result)
	}
}

func TestFormatDelta_resolved(t *testing.T) {
	result := FormatDelta(5, 3)
	if result != "2 resolved (total: 3)" {
		t.Errorf("expected '2 resolved (total: 3)', got: %s", result)
	}
}

func TestFormatDelta_no_change(t *testing.T) {
	result := FormatDelta(3, 3)
	if result != "No changes (total: 3)" {
		t.Errorf("expected 'No changes (total: 3)', got: %s", result)
	}
}

func TestWatch_calls_handler_on_change(t *testing.T) {
	dir := t.TempDir()

	// Create initial lockfile
	gosum := filepath.Join(dir, "go.sum")
	if err := os.WriteFile(gosum, []byte("initial"), 0644); err != nil {
		t.Fatalf("failed to create initial file: %v", err)
	}

	// Track handler calls
	var handlerCalls int
	var receivedEvents []ChangeEvent

	cfg := WatchConfig{
		Root:         dir,
		PollInterval: 50 * time.Millisecond,
		OnChange: func(ctx context.Context, events []ChangeEvent) error {
			handlerCalls++
			receivedEvents = append(receivedEvents, events...)
			// Cancel context after first call
			return context.Canceled
		},
	}

	// Start watch in a goroutine
	go func() {
		time.Sleep(75 * time.Millisecond)
		if err := os.WriteFile(gosum, []byte("modified"), 0644); err != nil {
			t.Errorf("failed to modify file: %v", err)
		}
	}()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Run watch - it will exit when context is cancelled
	Watch(ctx, cfg)

	// Verify handler was called
	if handlerCalls == 0 {
		t.Error("expected OnChange handler to be called, but it wasn't")
	}

	// Verify we received an event for go.sum
	if len(receivedEvents) == 0 {
		t.Error("expected at least one change event, got none")
	} else {
		found := false
		for _, e := range receivedEvents {
			if e.File == "go.sum" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected go.sum in events, got: %v", receivedEvents)
		}
	}
}
