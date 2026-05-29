package cra

import (
	"strings"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestGeneratePlan_no_failures(t *testing.T) {
	result := models.CRAResult{
		ProductName: "test-product",
		Version:     "1.0.0",
		Date:        time.Now().UTC(),
		Checks: []models.CRACheck{
			{
				ID:     "sbom-exists",
				Title:  "SBOM exists",
				Status: models.CRAPass,
			},
			{
				ID:     "vuln-check",
				Title:  "Vulnerability check",
				Status: models.CRAPass,
			},
			{
				ID:     "support-end",
				Title:  "Support end date",
				Status: models.CRANA,
			},
		},
	}

	plan := GeneratePlan(result)
	if len(plan.Actions) != 0 {
		t.Errorf("expected 0 actions, got %d", len(plan.Actions))
	}
	if plan.TotalEffortHours != 0 {
		t.Errorf("expected 0 hours, got %d", plan.TotalEffortHours)
	}
}

func TestGeneratePlan_sorted_by_priority(t *testing.T) {
	result := models.CRAResult{
		ProductName: "test-product",
		Version:     "1.0.0",
		Date:        time.Now().UTC(),
		Checks: []models.CRACheck{
			{
				ID:       "medium-warn",
				Title:    "Medium warning",
				Article:  "Art 1",
				Status:   models.CRAWarn,
				Severity: models.SeverityMedium,
			},
			{
				ID:       "critical-fail",
				Title:    "Critical failure",
				Article:  "Art 2",
				Status:   models.CRAFail,
				Severity: models.SeverityCritical,
			},
			{
				ID:       "high-fail",
				Title:    "High failure",
				Article:  "Art 3",
				Status:   models.CRAFail,
				Severity: models.SeverityHigh,
			},
			{
				ID:       "low-warn",
				Title:    "Low warning",
				Article:  "Art 4",
				Status:   models.CRAWarn,
				Severity: models.SeverityLow,
			},
		},
	}

	plan := GeneratePlan(result)
	if len(plan.Actions) != 4 {
		t.Errorf("expected 4 actions, got %d", len(plan.Actions))
	}

	// Verify sorted by priority, then by effort
	// critical-fail: P1 (16h)
	// high-fail: P2 (8h)
	// low-warn: P4 (2h) - sorts before medium-warn (4h) within same priority
	// medium-warn: P4 (4h)
	if plan.Actions[0].CheckID != "critical-fail" {
		t.Errorf("expected critical-fail first, got %s", plan.Actions[0].CheckID)
	}
	if plan.Actions[1].CheckID != "high-fail" {
		t.Errorf("expected high-fail second, got %s", plan.Actions[1].CheckID)
	}
	if plan.Actions[2].CheckID != "low-warn" {
		t.Errorf("expected low-warn third (P4, 2h), got %s", plan.Actions[2].CheckID)
	}
	if plan.Actions[3].CheckID != "medium-warn" {
		t.Errorf("expected medium-warn fourth (P4, 4h), got %s", plan.Actions[3].CheckID)
	}
}

func TestGeneratePlan_total_effort(t *testing.T) {
	result := models.CRAResult{
		ProductName: "test-product",
		Version:     "1.0.0",
		Date:        time.Now().UTC(),
		Checks: []models.CRACheck{
			{
				ID:       "critical",
				Title:    "Critical",
				Status:   models.CRAFail,
				Severity: models.SeverityCritical, // 16 hours
			},
			{
				ID:       "high",
				Title:    "High",
				Status:   models.CRAFail,
				Severity: models.SeverityHigh, // 8 hours
			},
			{
				ID:       "medium",
				Title:    "Medium",
				Status:   models.CRAWarn,
				Severity: models.SeverityMedium, // 4 hours
			},
		},
	}

	plan := GeneratePlan(result)
	expected := 16 + 8 + 4
	if plan.TotalEffortHours != expected {
		t.Errorf("expected %d total hours, got %d", expected, plan.TotalEffortHours)
	}
}

func TestInferRole(t *testing.T) {
	tests := []struct {
		name     string
		checkID  string
		expected RemediationRole
	}{
		{"sbom-related", "sbom-exists", RoleEngineering},
		{"hash-related", "sbom-hashes", RoleEngineering},
		{"vuln-related", "vuln-detected", RoleEngineering},
		{"version-related", "version-check", RoleEngineering},
		{"secure-related", "secure-defaults", RoleEngineering},
		{"action-related", "github-action-pin", RoleEngineering},
		{"disclosure-related", "disclosure-policy", RoleSecurity},
		{"csirt-related", "csirt-contact", RoleSecurity},
		{"incident-related", "incident-reporting", RoleSecurity},
		{"reporting-related", "reporting-requirement", RoleSecurity},
		{"contact-related", "contact-info", RoleSecurity},
		{"support-related", "support-end-date", RoleLegal},
		{"manufacturer-related", "manufacturer-info", RoleLegal},
		{"classification-related", "classification-check", RoleLegal},
		{"conformity-related", "conformity-statement", RoleLegal},
		{"unknown", "unknown-check-id", RoleEngineering},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := models.CRACheck{ID: tt.checkID}
			role := inferRole(check)
			if role != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, role)
			}
		})
	}
}

func TestInferEffort(t *testing.T) {
	tests := []struct {
		name     string
		severity models.Severity
		expected int
	}{
		{"critical", models.SeverityCritical, 16},
		{"high", models.SeverityHigh, 8},
		{"medium", models.SeverityMedium, 4},
		{"low", models.SeverityLow, 2},
		{"none", models.SeverityNone, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := models.CRACheck{Severity: tt.severity}
			effort := inferEffort(check)
			if effort != tt.expected {
				t.Errorf("expected %d hours, got %d", tt.expected, effort)
			}
		})
	}
}

func TestInferPriority(t *testing.T) {
	tests := []struct {
		name     string
		severity models.Severity
		status   models.CRACheckStatus
		expected int
	}{
		{"critical", models.SeverityCritical, models.CRAFail, 1},
		{"critical-warn", models.SeverityCritical, models.CRAWarn, 1},
		{"high-fail", models.SeverityHigh, models.CRAFail, 2},
		{"high-warn", models.SeverityHigh, models.CRAWarn, 2},
		{"medium-fail", models.SeverityMedium, models.CRAFail, 3},
		{"medium-warn", models.SeverityMedium, models.CRAWarn, 4},
		{"low-warn", models.SeverityLow, models.CRAWarn, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := models.CRACheck{
				Severity: tt.severity,
				Status:   tt.status,
			}
			priority := inferPriority(check)
			if priority != tt.expected {
				t.Errorf("expected priority %d, got %d", tt.expected, priority)
			}
		})
	}
}

func TestFormatPlan_empty(t *testing.T) {
	plan := RemediationPlan{
		TotalEffortHours: 0,
		Actions:          []RemediationAction{},
	}

	output := FormatPlan(plan)
	if !strings.Contains(output, "No remediation actions needed") {
		t.Errorf("expected 'No remediation actions needed' message, got:\n%s", output)
	}
	if !strings.Contains(output, "All CRA checks pass") {
		t.Errorf("expected 'All CRA checks pass' message, got:\n%s", output)
	}
}

func TestFormatPlan_has_header(t *testing.T) {
	plan := RemediationPlan{
		TotalEffortHours: 24,
		Actions: []RemediationAction{
			{
				CheckID:     "sbom-exists",
				Title:       "Software Bill of Materials exists",
				Description: "Run a dependency scan",
				Role:        RoleEngineering,
				EffortHours: 16,
				Priority:    1,
				Article:     "Annex I",
			},
			{
				CheckID:     "disclosure-policy",
				Title:       "Disclosure policy documented",
				Description: "Create security.txt",
				Role:        RoleSecurity,
				EffortHours: 8,
				Priority:    2,
				Article:     "Article 14",
			},
		},
	}

	output := FormatPlan(plan)

	// Check for headers
	if !strings.Contains(output, "CRA Remediation Plan") {
		t.Errorf("expected 'CRA Remediation Plan' header")
	}
	if !strings.Contains(output, "PRI") || !strings.Contains(output, "ROLE") ||
		!strings.Contains(output, "EFFORT") || !strings.Contains(output, "REF") ||
		!strings.Contains(output, "ACTION") {
		t.Errorf("expected column headers in output")
	}

	// Check for content (titles and descriptions are in output, not check IDs)
	if !strings.Contains(output, "Software Bill of Materials exists") {
		t.Errorf("expected 'Software Bill of Materials exists' in output")
	}
	if !strings.Contains(output, "Disclosure policy documented") {
		t.Errorf("expected 'Disclosure policy documented' in output")
	}

	// Check for priority markers
	if !strings.Contains(output, "P1") {
		t.Errorf("expected 'P1' priority marker")
	}
	if !strings.Contains(output, "P2") {
		t.Errorf("expected 'P2' priority marker")
	}

	// Check for effort display
	if !strings.Contains(output, "16h") {
		t.Errorf("expected '16h' effort display")
	}
	if !strings.Contains(output, "8h") {
		t.Errorf("expected '8h' effort display")
	}

	// Check for role summary
	if !strings.Contains(output, "Effort by role:") {
		t.Errorf("expected 'Effort by role:' summary")
	}
	if !strings.Contains(output, "engineering=16h") {
		t.Errorf("expected 'engineering=16h' in role summary")
	}
	if !strings.Contains(output, "security=8h") {
		t.Errorf("expected 'security=8h' in role summary")
	}
}

func TestFormatPlan_descriptions_included(t *testing.T) {
	plan := RemediationPlan{
		TotalEffortHours: 16,
		Actions: []RemediationAction{
			{
				CheckID:     "test-check",
				Title:       "Test check",
				Description: "This is a test description",
				Role:        RoleEngineering,
				EffortHours: 16,
				Priority:    1,
				Article:     "Art 1",
			},
		},
	}

	output := FormatPlan(plan)
	if !strings.Contains(output, "This is a test description") {
		t.Errorf("expected description in output")
	}
}

func TestFormatPlan_multiple_roles(t *testing.T) {
	plan := RemediationPlan{
		TotalEffortHours: 30,
		Actions: []RemediationAction{
			{
				CheckID:     "sbom-check",
				Title:       "SBOM check",
				Role:        RoleEngineering,
				EffortHours: 16,
				Priority:    1,
				Article:     "Art 1",
			},
			{
				CheckID:     "disclosure",
				Title:       "Disclosure",
				Role:        RoleSecurity,
				EffortHours: 8,
				Priority:    2,
				Article:     "Art 2",
			},
			{
				CheckID:     "support",
				Title:       "Support",
				Role:        RoleLegal,
				EffortHours: 6,
				Priority:    3,
				Article:     "Art 3",
			},
		},
	}

	output := FormatPlan(plan)
	if !strings.Contains(output, "engineering=16h") {
		t.Errorf("expected engineering hours in summary")
	}
	if !strings.Contains(output, "security=8h") {
		t.Errorf("expected security hours in summary")
	}
	if !strings.Contains(output, "legal=6h") {
		t.Errorf("expected legal hours in summary")
	}
}

func TestMapCheckToAction(t *testing.T) {
	check := models.CRACheck{
		ID:          "test-check",
		Title:       "Test Check",
		Article:     "Art 5",
		Status:      models.CRAFail,
		Severity:    models.SeverityCritical,
		Remediation: "Fix this issue",
	}

	action := mapCheckToAction(check)

	if action.CheckID != "test-check" {
		t.Errorf("expected CheckID 'test-check', got %s", action.CheckID)
	}
	if action.Title != "Test Check" {
		t.Errorf("expected Title 'Test Check', got %s", action.Title)
	}
	if action.Article != "Art 5" {
		t.Errorf("expected Article 'Art 5', got %s", action.Article)
	}
	if action.Description != "Fix this issue" {
		t.Errorf("expected Description 'Fix this issue', got %s", action.Description)
	}
	if action.EffortHours != 16 {
		t.Errorf("expected EffortHours 16, got %d", action.EffortHours)
	}
	if action.Priority != 1 {
		t.Errorf("expected Priority 1, got %d", action.Priority)
	}
	if action.Role != RoleEngineering {
		t.Errorf("expected Role %s, got %s", RoleEngineering, action.Role)
	}
}
