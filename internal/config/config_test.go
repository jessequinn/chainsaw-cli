package config

import (
	"testing"
)

func TestDefaultConfig_returns_expected_defaults(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	if cfg.Path != "." {
		t.Errorf("Path: got %q, want %q", cfg.Path, ".")
	}
	if cfg.Format != "text" {
		t.Errorf("Format: got %q, want %q", cfg.Format, "text")
	}
	if cfg.Ecosystems != nil {
		t.Errorf("Ecosystems: got %v, want nil", cfg.Ecosystems)
	}
	if cfg.FailOn != "NONE" {
		t.Errorf("FailOn: got %q, want %q", cfg.FailOn, "NONE")
	}
	if cfg.PolicyPath != ".chainsaw.yaml" {
		t.Errorf("PolicyPath: got %q, want %q", cfg.PolicyPath, ".chainsaw.yaml")
	}
}

func TestDefaultConfig_returns_new_instance_each_call(t *testing.T) {
	t.Parallel()

	cfg1 := DefaultConfig()
	cfg2 := DefaultConfig()

	if cfg1 == cfg2 {
		t.Error("DefaultConfig() returned the same pointer on consecutive calls; want different instances")
	}

	if cfg1.Path != cfg2.Path || cfg1.Format != cfg2.Format {
		t.Error("DefaultConfig() instances have different values; want identical values")
	}
}

func TestConfig_zero_value(t *testing.T) {
	t.Parallel()

	var cfg Config

	if cfg.Path != "" {
		t.Errorf("Path: got %q, want empty string", cfg.Path)
	}
	if cfg.Format != "" {
		t.Errorf("Format: got %q, want empty string", cfg.Format)
	}
	if cfg.Ecosystems != nil {
		t.Errorf("Ecosystems: got %v, want nil", cfg.Ecosystems)
	}
	if cfg.FailOn != "" {
		t.Errorf("FailOn: got %q, want empty string", cfg.FailOn)
	}
	if cfg.PolicyPath != "" {
		t.Errorf("PolicyPath: got %q, want empty string", cfg.PolicyPath)
	}
}
