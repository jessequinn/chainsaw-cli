package cra

import (
	"fmt"
	"sort"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// RemediationRole identifies who should own a remediation action.
type RemediationRole string

const (
	RoleEngineering RemediationRole = "engineering"
	RoleSecurity    RemediationRole = "security"
	RoleLegal       RemediationRole = "legal"
)

// RemediationAction is a single step in a remediation plan.
type RemediationAction struct {
	CheckID     string          `json:"check_id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Role        RemediationRole `json:"role"`
	EffortHours int             `json:"effort_hours"`
	Priority    int             `json:"priority"` // 1 (highest) - 5 (lowest)
	Article     string          `json:"article"`
}

// RemediationPlan is a sorted list of actions derived from CRA assessment.
type RemediationPlan struct {
	TotalEffortHours int                 `json:"total_effort_hours"`
	Actions          []RemediationAction `json:"actions"`
}

// GeneratePlan creates a remediation plan from failing/warning CRA checks.
func GeneratePlan(result models.CRAResult) RemediationPlan {
	var actions []RemediationAction

	for _, check := range result.Checks {
		if check.Status == models.CRAPass || check.Status == models.CRANA {
			continue
		}
		action := mapCheckToAction(check)
		actions = append(actions, action)
	}

	// Sort by priority (ascending), then effort (ascending).
	sort.Slice(actions, func(i, j int) bool {
		if actions[i].Priority != actions[j].Priority {
			return actions[i].Priority < actions[j].Priority
		}
		return actions[i].EffortHours < actions[j].EffortHours
	})

	total := 0
	for _, a := range actions {
		total += a.EffortHours
	}

	return RemediationPlan{
		TotalEffortHours: total,
		Actions:          actions,
	}
}

// FormatPlan formats the remediation plan as a human-readable string.
func FormatPlan(plan RemediationPlan) string {
	if len(plan.Actions) == 0 {
		return "No remediation actions needed. All CRA checks pass.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CRA Remediation Plan (%d actions, ~%d hours estimated)\n", len(plan.Actions), plan.TotalEffortHours))
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	sb.WriteString(fmt.Sprintf("%-4s %-12s %-10s %-6s %s\n", "PRI", "ROLE", "EFFORT", "REF", "ACTION"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for _, a := range plan.Actions {
		effort := fmt.Sprintf("%dh", a.EffortHours)
		sb.WriteString(fmt.Sprintf("P%-3d %-12s %-10s %-6s %s\n", a.Priority, a.Role, effort, a.Article, a.Title))
		if a.Description != "" {
			sb.WriteString(fmt.Sprintf("     %s\n", a.Description))
		}
	}

	sb.WriteString(strings.Repeat("-", 80) + "\n")
	// Summary by role
	roleHours := map[RemediationRole]int{}
	for _, a := range plan.Actions {
		roleHours[a.Role] += a.EffortHours
	}
	sb.WriteString("Effort by role: ")
	parts := []string{}
	for _, role := range []RemediationRole{RoleEngineering, RoleSecurity, RoleLegal} {
		if h := roleHours[role]; h > 0 {
			parts = append(parts, fmt.Sprintf("%s=%dh", role, h))
		}
	}
	sb.WriteString(strings.Join(parts, ", ") + "\n")

	return sb.String()
}

func mapCheckToAction(check models.CRACheck) RemediationAction {
	role := inferRole(check)
	effort := inferEffort(check)
	priority := inferPriority(check)

	return RemediationAction{
		CheckID:     check.ID,
		Title:       check.Title,
		Description: check.Remediation,
		Role:        role,
		EffortHours: effort,
		Priority:    priority,
		Article:     check.Article,
	}
}

func inferRole(check models.CRACheck) RemediationRole {
	id := strings.ToLower(check.ID)
	switch {
	case strings.Contains(id, "sbom") || strings.Contains(id, "hash") ||
		strings.Contains(id, "vuln") || strings.Contains(id, "version") ||
		strings.Contains(id, "secure") || strings.Contains(id, "action"):
		return RoleEngineering
	case strings.Contains(id, "disclosure") || strings.Contains(id, "security") ||
		strings.Contains(id, "csirt") || strings.Contains(id, "incident") ||
		strings.Contains(id, "reporting") || strings.Contains(id, "contact"):
		return RoleSecurity
	case strings.Contains(id, "support") || strings.Contains(id, "manufacturer") ||
		strings.Contains(id, "classification") || strings.Contains(id, "conformity"):
		return RoleLegal
	default:
		return RoleEngineering
	}
}

func inferEffort(check models.CRACheck) int {
	switch check.Severity {
	case models.SeverityCritical:
		return 16
	case models.SeverityHigh:
		return 8
	case models.SeverityMedium:
		return 4
	default:
		return 2
	}
}

func inferPriority(check models.CRACheck) int {
	switch {
	case check.Severity == models.SeverityCritical:
		return 1
	case check.Severity == models.SeverityHigh:
		return 2
	case check.Status == models.CRAFail:
		return 3
	case check.Status == models.CRAWarn:
		return 4
	default:
		return 5
	}
}
