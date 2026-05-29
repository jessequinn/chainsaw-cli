package policy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestLoadPolicy_with_extends_local(t *testing.T) {
	dir := t.TempDir()

	// Create parent policy
	parentPath := filepath.Join(dir, "parent.yaml")
	parentContent := `
policy:
  fail-on: MEDIUM
  ignore:
    - CVE-2024-0001
`
	if err := os.WriteFile(parentPath, []byte(parentContent), 0644); err != nil {
		t.Fatalf("write parent policy: %v", err)
	}

	// Create child policy that extends parent
	childPath := filepath.Join(dir, "child.yaml")
	childContent := `
extends: parent.yaml
policy:
  fail-on: HIGH
  ignore: []
`
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatalf("write child policy: %v", err)
	}

	p, err := LoadPolicy(context.Background(), childPath)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}

	// Child's fail-on should override parent's
	if p.FailOn != models.SeverityHigh {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityHigh)
	}

	// Parent's ignore should be preserved (merged)
	if len(p.Ignore) != 1 || p.Ignore[0].ID != "CVE-2024-0001" {
		t.Errorf("Ignore = %v, want [CVE-2024-0001]", p.Ignore)
	}
}

func TestLoadPolicy_extends_merges_ignore(t *testing.T) {
	dir := t.TempDir()

	// Create parent policy with one ignore rule
	parentPath := filepath.Join(dir, "parent.yaml")
	parentContent := `
policy:
  fail-on: MEDIUM
  ignore:
    - CVE-2024-0001
`
	if err := os.WriteFile(parentPath, []byte(parentContent), 0644); err != nil {
		t.Fatalf("write parent policy: %v", err)
	}

	// Create child policy that extends parent and adds another ignore rule
	childPath := filepath.Join(dir, "child.yaml")
	childContent := `
extends: parent.yaml
policy:
  ignore:
    - CVE-2024-0002
`
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatalf("write child policy: %v", err)
	}

	p, err := LoadPolicy(context.Background(), childPath)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}

	// Both ignore rules should be present
	if len(p.Ignore) != 2 {
		t.Errorf("Ignore count = %d, want 2", len(p.Ignore))
	}

	ids := make(map[string]bool)
	for _, rule := range p.Ignore {
		ids[rule.ID] = true
	}
	if !ids["CVE-2024-0001"] || !ids["CVE-2024-0002"] {
		t.Errorf("Ignore list missing expected CVEs: %v", ids)
	}
}

func TestLoadPolicy_extends_depth_limit(t *testing.T) {
	dir := t.TempDir()

	// Create 4 levels: base -> a -> b -> c -> d (should fail at depth 3)
	basePath := filepath.Join(dir, "base.yaml")
	baseContent := `
policy:
  fail-on: LOW
`
	if err := os.WriteFile(basePath, []byte(baseContent), 0644); err != nil {
		t.Fatalf("write base policy: %v", err)
	}

	aPath := filepath.Join(dir, "a.yaml")
	aContent := `
extends: base.yaml
policy: {}
`
	if err := os.WriteFile(aPath, []byte(aContent), 0644); err != nil {
		t.Fatalf("write a policy: %v", err)
	}

	bPath := filepath.Join(dir, "b.yaml")
	bContent := `
extends: a.yaml
policy: {}
`
	if err := os.WriteFile(bPath, []byte(bContent), 0644); err != nil {
		t.Fatalf("write b policy: %v", err)
	}

	cPath := filepath.Join(dir, "c.yaml")
	cContent := `
extends: b.yaml
policy: {}
`
	if err := os.WriteFile(cPath, []byte(cContent), 0644); err != nil {
		t.Fatalf("write c policy: %v", err)
	}

	dPath := filepath.Join(dir, "d.yaml")
	dContent := `
extends: c.yaml
policy: {}
`
	if err := os.WriteFile(dPath, []byte(dContent), 0644); err != nil {
		t.Fatalf("write d policy: %v", err)
	}

	_, err := LoadPolicy(context.Background(), dPath)
	if err == nil {
		t.Fatal("expected error for exceeding inheritance depth, got nil")
	}
	if !contains(err.Error(), "depth exceeds maximum") {
		t.Errorf("error message = %q, want to contain 'depth exceeds maximum'", err.Error())
	}
}

func TestLoadPolicy_extends_absolute_path(t *testing.T) {
	dir := t.TempDir()

	// Create parent policy
	parentPath := filepath.Join(dir, "parent.yaml")
	parentContent := `
policy:
  fail-on: MEDIUM
`
	if err := os.WriteFile(parentPath, []byte(parentContent), 0644); err != nil {
		t.Fatalf("write parent policy: %v", err)
	}

	// Create child policy with absolute path to parent
	childPath := filepath.Join(dir, "child.yaml")
	childContent := fmt.Sprintf(`
extends: %s
policy:
  fail-on: HIGH
`, parentPath)
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatalf("write child policy: %v", err)
	}

	p, err := LoadPolicy(context.Background(), childPath)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}

	if p.FailOn != models.SeverityHigh {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityHigh)
	}
}

func TestLoadPolicy_extends_remote(t *testing.T) {
	// Create a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/parent.yaml" {
			w.Header().Set("Content-Type", "application/yaml")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `
policy:
  fail-on: MEDIUM
`)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	dir := t.TempDir()

	// Create local child policy that extends remote parent
	childPath := filepath.Join(dir, "child.yaml")
	childContent := fmt.Sprintf(`
extends: %s/parent.yaml
policy:
  fail-on: HIGH
`, server.URL)
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatalf("write child policy: %v", err)
	}

	p, err := LoadPolicy(context.Background(), childPath)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}

	if p.FailOn != models.SeverityHigh {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityHigh)
	}
}

func TestLoadPolicy_extends_remote_404(t *testing.T) {
	// Create a test HTTP server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	dir := t.TempDir()

	// Create local child policy that extends non-existent remote parent
	childPath := filepath.Join(dir, "child.yaml")
	childContent := fmt.Sprintf(`
extends: %s/parent.yaml
policy:
  fail-on: HIGH
`, server.URL)
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatalf("write child policy: %v", err)
	}

	_, err := LoadPolicy(context.Background(), childPath)
	if err == nil {
		t.Fatal("expected error for remote policy 404, got nil")
	}
	if !contains(err.Error(), "HTTP") {
		t.Errorf("error message = %q, want to contain 'HTTP'", err.Error())
	}
}

func TestLoadPolicy_extends_remote_cannot_extend_further(t *testing.T) {
	// Create a test HTTP server that serves a policy with extends
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `
extends: another.yaml
policy:
  fail-on: MEDIUM
`)
	}))
	defer server.Close()

	dir := t.TempDir()

	// Create local child policy that extends remote parent
	childPath := filepath.Join(dir, "child.yaml")
	childContent := fmt.Sprintf(`
extends: %s/parent.yaml
policy:
  fail-on: HIGH
`, server.URL)
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatalf("write child policy: %v", err)
	}

	_, err := LoadPolicy(context.Background(), childPath)
	if err == nil {
		t.Fatal("expected error for remote policy with extends, got nil")
	}
	if !contains(err.Error(), "nested extends") {
		t.Errorf("error message = %q, want to contain 'nested extends'", err.Error())
	}
}

func TestMergePolicy_child_overrides_failon(t *testing.T) {
	parent := &Policy{FailOn: models.SeverityMedium}
	child := &Policy{FailOn: models.SeverityHigh}

	merged := mergePolicy(parent, child)
	if merged.FailOn != models.SeverityHigh {
		t.Errorf("FailOn = %q, want %q", merged.FailOn, models.SeverityHigh)
	}
}

func TestMergePolicy_child_none_uses_parent(t *testing.T) {
	parent := &Policy{FailOn: models.SeverityMedium}
	child := &Policy{FailOn: models.SeverityNone}

	merged := mergePolicy(parent, child)
	if merged.FailOn != models.SeverityMedium {
		t.Errorf("FailOn = %q, want %q", merged.FailOn, models.SeverityMedium)
	}
}

func TestMergePolicy_combines_ignore_lists(t *testing.T) {
	parent := &Policy{
		Ignore: []IgnoreRule{
			{ID: "CVE-2024-0001"},
			{ID: "CVE-2024-0002"},
		},
	}
	child := &Policy{
		Ignore: []IgnoreRule{
			{ID: "CVE-2024-0003"},
		},
	}

	merged := mergePolicy(parent, child)
	if len(merged.Ignore) != 3 {
		t.Errorf("Ignore count = %d, want 3", len(merged.Ignore))
	}

	ids := make(map[string]bool)
	for _, rule := range merged.Ignore {
		ids[rule.ID] = true
	}
	expectedIDs := map[string]bool{
		"CVE-2024-0001": true,
		"CVE-2024-0002": true,
		"CVE-2024-0003": true,
	}
	if len(ids) != len(expectedIDs) {
		t.Errorf("unexpected ignore IDs: %v", ids)
	}
}

func TestMergePolicy_deduplicates_ignore_lists(t *testing.T) {
	parent := &Policy{
		Ignore: []IgnoreRule{
			{ID: "CVE-2024-0001"},
		},
	}
	child := &Policy{
		Ignore: []IgnoreRule{
			{ID: "CVE-2024-0001"},
			{ID: "CVE-2024-0002"},
		},
	}

	merged := mergePolicy(parent, child)
	if len(merged.Ignore) != 2 {
		t.Errorf("Ignore count = %d, want 2 (deduplicated)", len(merged.Ignore))
	}

	ids := make(map[string]bool)
	for _, rule := range merged.Ignore {
		ids[rule.ID] = true
	}
	if !ids["CVE-2024-0001"] || !ids["CVE-2024-0002"] {
		t.Errorf("unexpected ignore IDs: %v", ids)
	}
}

func TestMergePolicy_ecosystems_merge(t *testing.T) {
	parent := &Policy{
		Ecosystems: map[string]EcosystemOverride{
			"go": {FailOn: models.SeverityMedium},
		},
	}
	child := &Policy{
		Ecosystems: map[string]EcosystemOverride{
			"npm": {FailOn: models.SeverityHigh},
		},
	}

	merged := mergePolicy(parent, child)
	if len(merged.Ecosystems) != 2 {
		t.Errorf("Ecosystems count = %d, want 2", len(merged.Ecosystems))
	}

	if _, ok := merged.Ecosystems["go"]; !ok {
		t.Error("expected 'go' ecosystem in merged policy")
	}
	if _, ok := merged.Ecosystems["npm"]; !ok {
		t.Error("expected 'npm' ecosystem in merged policy")
	}
}

func TestMergePolicy_ecosystems_child_overrides(t *testing.T) {
	parent := &Policy{
		Ecosystems: map[string]EcosystemOverride{
			"go": {FailOn: models.SeverityMedium},
		},
	}
	child := &Policy{
		Ecosystems: map[string]EcosystemOverride{
			"go": {FailOn: models.SeverityCritical},
		},
	}

	merged := mergePolicy(parent, child)
	if len(merged.Ecosystems) != 1 {
		t.Errorf("Ecosystems count = %d, want 1", len(merged.Ecosystems))
	}

	goOverride, ok := merged.Ecosystems["go"]
	if !ok {
		t.Fatal("expected 'go' ecosystem in merged policy")
	}
	if goOverride.FailOn != models.SeverityCritical {
		t.Errorf("go FailOn = %q, want %q", goOverride.FailOn, models.SeverityCritical)
	}
}

func TestMergePolicy_cra_child_overrides(t *testing.T) {
	parent := &Policy{
		CRA: CRAPolicy{
			RequiredScore:   70,
			Manufacturer:    "Parent Corp",
			SecurityContact: "parent@example.com",
		},
	}
	child := &Policy{
		CRA: CRAPolicy{
			RequiredScore:   85,
			Manufacturer:    "Child Corp",
		},
	}

	merged := mergePolicy(parent, child)
	if merged.CRA.RequiredScore != 85 {
		t.Errorf("CRA.RequiredScore = %d, want 85", merged.CRA.RequiredScore)
	}
	if merged.CRA.Manufacturer != "Child Corp" {
		t.Errorf("CRA.Manufacturer = %q, want %q", merged.CRA.Manufacturer, "Child Corp")
	}
	if merged.CRA.SecurityContact != "parent@example.com" {
		t.Errorf("CRA.SecurityContact = %q, want %q", merged.CRA.SecurityContact, "parent@example.com")
	}
}

func TestMergePolicy_licences_child_overrides(t *testing.T) {
	parent := &Policy{
		Licences: LicencePolicy{
			Mode:     "deny",
			DenyList: []string{"GPL-3.0"},
		},
	}
	child := &Policy{
		Licences: LicencePolicy{
			Mode:      "allow",
			AllowList: []string{"MIT", "Apache-2.0"},
		},
	}

	merged := mergePolicy(parent, child)
	if merged.Licences.Mode != "allow" {
		t.Errorf("Licences.Mode = %q, want %q", merged.Licences.Mode, "allow")
	}
	if len(merged.Licences.AllowList) != 2 {
		t.Errorf("Licences.AllowList length = %d, want 2", len(merged.Licences.AllowList))
	}
	if len(merged.Licences.DenyList) != 0 {
		t.Errorf("Licences.DenyList length = %d, want 0", len(merged.Licences.DenyList))
	}
}

func TestLoadPolicy_extends_with_subdirectories(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory
	subdir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	// Create parent policy in subdirectory
	parentPath := filepath.Join(subdir, "parent.yaml")
	parentContent := `
policy:
  fail-on: MEDIUM
`
	if err := os.WriteFile(parentPath, []byte(parentContent), 0644); err != nil {
		t.Fatalf("write parent policy: %v", err)
	}

	// Create child policy in subdirectory that extends parent
	childPath := filepath.Join(subdir, "child.yaml")
	childContent := `
extends: parent.yaml
policy:
  fail-on: HIGH
`
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatalf("write child policy: %v", err)
	}

	p, err := LoadPolicy(context.Background(), childPath)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}

	if p.FailOn != models.SeverityHigh {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityHigh)
	}
}

func TestLoadPolicy_extends_invalid_parent_path(t *testing.T) {
	dir := t.TempDir()

	// Create child policy with non-existent parent
	childPath := filepath.Join(dir, "child.yaml")
	childContent := `
extends: /nonexistent/parent.yaml
policy:
  fail-on: HIGH
`
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatalf("write child policy: %v", err)
	}

	_, err := LoadPolicy(context.Background(), childPath)
	if err == nil {
		t.Fatal("expected error for non-existent parent, got nil")
	}
	if !contains(err.Error(), "loading parent policy") {
		t.Errorf("error message = %q, want to contain 'loading parent policy'", err.Error())
	}
}

func TestLoadPolicy_extends_with_cra_and_supply_chain(t *testing.T) {
	dir := t.TempDir()

	// Create parent policy with CRA settings
	parentPath := filepath.Join(dir, "parent.yaml")
	parentContent := `
policy:
  fail-on: MEDIUM
cra:
  required-score: 70
  manufacturer: "Parent Corp"
supply-chain:
  min-pinning-score: 60
`
	if err := os.WriteFile(parentPath, []byte(parentContent), 0644); err != nil {
		t.Fatalf("write parent policy: %v", err)
	}

	// Create child policy that extends parent and overrides CRA
	childPath := filepath.Join(dir, "child.yaml")
	childContent := `
extends: parent.yaml
policy:
  fail-on: HIGH
cra:
  required-score: 85
`
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatalf("write child policy: %v", err)
	}

	p, err := LoadPolicy(context.Background(), childPath)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}

	if p.FailOn != models.SeverityHigh {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityHigh)
	}
	if p.CRA.RequiredScore != 85 {
		t.Errorf("CRA.RequiredScore = %d, want 85", p.CRA.RequiredScore)
	}
	if p.CRA.Manufacturer != "Parent Corp" {
		t.Errorf("CRA.Manufacturer = %q, want %q", p.CRA.Manufacturer, "Parent Corp")
	}
	if p.SupplyChain.MinPinningScore != 60 {
		t.Errorf("SupplyChain.MinPinningScore = %d, want 60", p.SupplyChain.MinPinningScore)
	}
}

func TestMergePolicy_supply_chain_child_overrides(t *testing.T) {
	parent := &Policy{
		SupplyChain: SupplyChainPolicy{
			MinPinningScore: 60,
			RequireSHAPins:  false,
		},
	}
	child := &Policy{
		SupplyChain: SupplyChainPolicy{
			MinPinningScore: 80,
			RequireSHAPins:  true,
		},
	}

	merged := mergePolicy(parent, child)
	if merged.SupplyChain.MinPinningScore != 80 {
		t.Errorf("SupplyChain.MinPinningScore = %d, want 80", merged.SupplyChain.MinPinningScore)
	}
	if !merged.SupplyChain.RequireSHAPins {
		t.Error("SupplyChain.RequireSHAPins = false, want true")
	}
}

// Helper function to check if a string contains a substring (reuse from policy_test.go)
func containsInheritance(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Verify that we're using the helper from the original test file
var _ = containsInheritance

// Unit tests for buildPolicy function
func TestBuildPolicy_converts_fail_on(t *testing.T) {
	pf := policyFile{
		Policy: policyCore{
			FailOn: models.SeverityHigh,
		},
	}

	p := buildPolicy(pf)
	if p.FailOn != models.SeverityHigh {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityHigh)
	}
}

func TestBuildPolicy_preserves_ignore_rules(t *testing.T) {
	rules := []IgnoreRule{
		{ID: "CVE-2024-0001", Reason: "test"},
		{ID: "CVE-2024-0002"},
	}
	pf := policyFile{
		Policy: policyCore{
			Ignore: rules,
		},
	}

	p := buildPolicy(pf)
	if len(p.Ignore) != 2 {
		t.Errorf("Ignore count = %d, want 2", len(p.Ignore))
	}
	if p.Ignore[0].ID != "CVE-2024-0001" {
		t.Errorf("first ignore ID = %q, want %q", p.Ignore[0].ID, "CVE-2024-0001")
	}
}

func TestBuildPolicy_top_level_licences_take_precedence(t *testing.T) {
	pf := policyFile{
		Policy: policyCore{
			Licences: LicencePolicy{
				Mode:     "allow",
				AllowList: []string{"MIT"},
			},
		},
		Licences: LicencePolicy{
			Mode:     "deny",
			DenyList: []string{"GPL-3.0"},
		},
	}

	p := buildPolicy(pf)
	if p.Licences.Mode != "deny" {
		t.Errorf("Licences.Mode = %q, want %q", p.Licences.Mode, "deny")
	}
	if len(p.Licences.DenyList) != 1 {
		t.Errorf("DenyList length = %d, want 1", len(p.Licences.DenyList))
	}
}
