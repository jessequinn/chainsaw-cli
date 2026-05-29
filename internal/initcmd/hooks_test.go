package initcmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteNativeHook_creates_file(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .git/hooks directory structure
	hooksDir := filepath.Join(tmpDir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatalf("failed to create .git/hooks: %v", err)
	}

	path, err := WriteNativeHook(tmpDir)
	if err != nil {
		t.Fatalf("WriteNativeHook() failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("hook file does not exist: %v", err)
	}

	// Verify file is executable
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat hook file: %v", err)
	}

	if info.Mode()&0111 == 0 {
		t.Errorf("hook file is not executable; mode=%o", info.Mode())
	}

	// Verify content contains expected strings
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read hook file: %v", err)
	}

	expectedStrings := []string{
		"#!/bin/sh",
		"pre-commit hook",
		"chainsaw scan",
	}
	for _, expected := range expectedStrings {
		if !contains(string(content), expected) {
			t.Errorf("hook content missing %q", expected)
		}
	}
}

func TestWriteNativeHook_no_git(t *testing.T) {
	tmpDir := t.TempDir()

	// Try to write without .git/hooks directory
	_, err := WriteNativeHook(tmpDir)
	if err == nil {
		t.Fatal("expected error when .git/hooks does not exist")
	}

	if !contains(err.Error(), ".git/hooks directory not found") {
		t.Errorf("error message does not mention .git/hooks: %v", err)
	}
}

func TestWriteNativeHook_no_overwrite(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .git/hooks directory with existing pre-commit hook
	hooksDir := filepath.Join(tmpDir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatalf("failed to create .git/hooks: %v", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte("existing hook"), 0755); err != nil {
		t.Fatalf("failed to create existing hook: %v", err)
	}

	_, err := WriteNativeHook(tmpDir)
	if err == nil {
		t.Fatal("expected error when hook already exists")
	}

	if !contains(err.Error(), "already exists") {
		t.Errorf("error message does not mention existing hook: %v", err)
	}
}

func TestWriteNativeHookForce_overwrites(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .git/hooks directory with existing pre-commit hook
	hooksDir := filepath.Join(tmpDir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatalf("failed to create .git/hooks: %v", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte("existing hook"), 0755); err != nil {
		t.Fatalf("failed to create existing hook: %v", err)
	}

	// Force should succeed
	path, err := WriteNativeHookForce(tmpDir)
	if err != nil {
		t.Fatalf("WriteNativeHookForce() failed: %v", err)
	}

	// Verify the file was overwritten with new content
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read hook file: %v", err)
	}

	if contains(string(content), "existing hook") {
		t.Error("hook was not overwritten; still contains old content")
	}

	if !contains(string(content), "Chainsaw pre-commit hook") {
		t.Error("hook does not contain expected content")
	}
}

func TestWritePreCommitConfig_creates_file(t *testing.T) {
	tmpDir := t.TempDir()

	path, err := WritePreCommitConfig(tmpDir)
	if err != nil {
		t.Fatalf("WritePreCommitConfig() failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config file does not exist: %v", err)
	}

	// Verify content
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	expectedStrings := []string{
		"pre-commit framework configuration",
		"chainsaw-scan",
		"chainsaw scan",
	}
	for _, expected := range expectedStrings {
		if !contains(string(content), expected) {
			t.Errorf("config content missing %q", expected)
		}
	}
}

func TestWritePreCommitConfig_no_overwrite(t *testing.T) {
	tmpDir := t.TempDir()

	// Create existing config file
	configPath := filepath.Join(tmpDir, ".pre-commit-config.yaml")
	if err := os.WriteFile(configPath, []byte("existing config"), 0644); err != nil {
		t.Fatalf("failed to create existing config: %v", err)
	}

	_, err := WritePreCommitConfig(tmpDir)
	if err == nil {
		t.Fatal("expected error when config already exists")
	}

	if !contains(err.Error(), "already exists") {
		t.Errorf("error message does not mention existing file: %v", err)
	}
}

func TestNativeHookTemplate_contains_lockfiles(t *testing.T) {
	lockfiles := []string{
		"go.sum",
		"package-lock.json",
		"pnpm-lock.yaml",
		"yarn.lock",
		"Cargo.lock",
		"mix.lock",
		"requirements.txt",
		"Pipfile.lock",
		"composer.lock",
	}

	for _, lockfile := range lockfiles {
		if !contains(nativeHookTemplate, lockfile) {
			t.Errorf("native hook template missing lockfile: %q", lockfile)
		}
	}
}

// helper function
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
