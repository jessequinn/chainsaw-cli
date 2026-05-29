package cra

import (
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestClassificationChecker_EmptyCategory(t *testing.T) {
	actx := &AssessmentContext{
		Config: &CRAConfig{
			ProductCategory: "",
		},
	}

	checker := &ClassificationChecker{}
	checks := checker.Check(actx)

	if len(checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(checks))
	}

	// First check should fail
	if checks[0].ID != "CRA-CLASS-001" {
		t.Errorf("check[0].ID = %q, want %q", checks[0].ID, "CRA-CLASS-001")
	}
	if checks[0].Status != models.CRAFail {
		t.Errorf("check[0].Status = %q, want %q", checks[0].Status, models.CRAFail)
	}
}

func TestClassificationChecker_InvalidCategory(t *testing.T) {
	actx := &AssessmentContext{
		Config: &CRAConfig{
			ProductCategory: "invalid-category",
		},
	}

	checker := &ClassificationChecker{}
	checks := checker.Check(actx)

	if len(checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(checks))
	}

	// First check should fail with invalid message
	if checks[0].Status != models.CRAFail {
		t.Errorf("check[0].Status = %q, want %q", checks[0].Status, models.CRAFail)
	}
	if !contains(checks[0].Details, "Invalid product-category") {
		t.Errorf("check[0].Details should mention invalid category, got: %s", checks[0].Details)
	}
}

func TestClassificationChecker_DefaultCategory(t *testing.T) {
	actx := &AssessmentContext{
		Config: &CRAConfig{
			ProductCategory: "default",
		},
	}

	checker := &ClassificationChecker{}
	checks := checker.Check(actx)

	if len(checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(checks))
	}

	// First check should pass
	if checks[0].ID != "CRA-CLASS-001" {
		t.Errorf("check[0].ID = %q, want %q", checks[0].ID, "CRA-CLASS-001")
	}
	if checks[0].Status != models.CRAPass {
		t.Errorf("check[0].Status = %q, want %q", checks[0].Status, models.CRAPass)
	}

	// Second check should pass (self-assessment)
	if checks[1].ID != "CRA-CLASS-002" {
		t.Errorf("check[1].ID = %q, want %q", checks[1].ID, "CRA-CLASS-002")
	}
	if checks[1].Status != models.CRAPass {
		t.Errorf("check[1].Status = %q, want %q", checks[1].Status, models.CRAPass)
	}
	if !contains(checks[1].Details, "internal conformity assessment") {
		t.Errorf("check[1].Details should mention internal assessment, got: %s", checks[1].Details)
	}
}

func TestClassificationChecker_ImportantClass1(t *testing.T) {
	actx := &AssessmentContext{
		Config: &CRAConfig{
			ProductCategory: "important-class-1",
		},
	}

	checker := &ClassificationChecker{}
	checks := checker.Check(actx)

	if len(checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(checks))
	}

	// First check should pass
	if checks[0].Status != models.CRAPass {
		t.Errorf("check[0].Status = %q, want %q", checks[0].Status, models.CRAPass)
	}

	// Second check should pass (self-assessment with harmonised standards)
	if checks[1].Status != models.CRAPass {
		t.Errorf("check[1].Status = %q, want %q", checks[1].Status, models.CRAPass)
	}
	if !contains(checks[1].Details, "harmonised standards") {
		t.Errorf("check[1].Details should mention harmonised standards, got: %s", checks[1].Details)
	}
}

func TestClassificationChecker_ImportantClass2(t *testing.T) {
	actx := &AssessmentContext{
		Config: &CRAConfig{
			ProductCategory: "important-class-2",
		},
	}

	checker := &ClassificationChecker{}
	checks := checker.Check(actx)

	if len(checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(checks))
	}

	// First check should pass
	if checks[0].Status != models.CRAPass {
		t.Errorf("check[0].Status = %q, want %q", checks[0].Status, models.CRAPass)
	}

	// Second check should warn (third-party assessment required)
	if checks[1].ID != "CRA-CLASS-002" {
		t.Errorf("check[1].ID = %q, want %q", checks[1].ID, "CRA-CLASS-002")
	}
	if checks[1].Status != models.CRAWarn {
		t.Errorf("check[1].Status = %q, want %q", checks[1].Status, models.CRAWarn)
	}
	if !contains(checks[1].Details, "third-party conformity assessment") {
		t.Errorf("check[1].Details should mention third-party assessment, got: %s", checks[1].Details)
	}
}

func TestClassificationChecker_Critical(t *testing.T) {
	actx := &AssessmentContext{
		Config: &CRAConfig{
			ProductCategory: "critical",
		},
	}

	checker := &ClassificationChecker{}
	checks := checker.Check(actx)

	if len(checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(checks))
	}

	// First check should pass
	if checks[0].Status != models.CRAPass {
		t.Errorf("check[0].Status = %q, want %q", checks[0].Status, models.CRAPass)
	}

	// Second check should warn (third-party assessment required)
	if checks[1].Status != models.CRAWarn {
		t.Errorf("check[1].Status = %q, want %q", checks[1].Status, models.CRAWarn)
	}
	if !contains(checks[1].Details, "third-party conformity assessment") {
		t.Errorf("check[1].Details should mention third-party assessment, got: %s", checks[1].Details)
	}
}

func TestClassificationChecker_NoConfig(t *testing.T) {
	actx := &AssessmentContext{
		Config: nil,
	}

	checker := &ClassificationChecker{}
	checks := checker.Check(actx)

	if len(checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(checks))
	}

	// First check should fail (no config)
	if checks[0].Status != models.CRAFail {
		t.Errorf("check[0].Status = %q, want %q", checks[0].Status, models.CRAFail)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
