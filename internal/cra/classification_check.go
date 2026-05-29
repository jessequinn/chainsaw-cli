package cra

import "github.com/chainsaw-dev/chainsaw/pkg/models"

// Valid product categories per CRA Annex III/IV.
const (
	CategoryDefault         = "default"
	CategoryImportantClass1 = "important-class-1"
	CategoryImportantClass2 = "important-class-2"
	CategoryCritical        = "critical"
)

var validCategories = map[string]bool{
	CategoryDefault:         true,
	CategoryImportantClass1: true,
	CategoryImportantClass2: true,
	CategoryCritical:        true,
}

// ClassificationChecker validates product category classification.
type ClassificationChecker struct{}

func (c *ClassificationChecker) Check(actx *AssessmentContext) []models.CRACheck {
	var checks []models.CRACheck

	category := ""
	if actx.Config != nil {
		category = actx.Config.ProductCategory
	}

	// Check 1: Product category declared
	if category == "" {
		checks = append(checks, models.CRACheck{
			ID:          "CRA-CLASS-001",
			Title:       "Product category declared",
			Article:     "Annex III/IV",
			Status:      models.CRAFail,
			Details:     "No product-category set in .chainsaw.yaml. Set to: default, important-class-1, important-class-2, or critical.",
			Severity:    models.SeverityHigh,
			Remediation: "Add product-category to .chainsaw.yaml with one of the valid values.",
		})
	} else if !validCategories[category] {
		checks = append(checks, models.CRACheck{
			ID:          "CRA-CLASS-001",
			Title:       "Product category declared",
			Article:     "Annex III/IV",
			Status:      models.CRAFail,
			Details:     "Invalid product-category: " + category + ". Must be: default, important-class-1, important-class-2, or critical.",
			Severity:    models.SeverityHigh,
			Remediation: "Update product-category in .chainsaw.yaml to a valid value.",
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:       "CRA-CLASS-001",
			Title:    "Product category declared",
			Article:  "Annex III/IV",
			Status:   models.CRAPass,
			Details:  "Product classified as: " + category,
			Severity: models.SeverityHigh,
		})
	}

	// Check 2: Conformity assessment requirements
	if category == "" || !validCategories[category] {
		// If category is not set or invalid, this check is N/A
		checks = append(checks, models.CRACheck{
			ID:       "CRA-CLASS-002",
			Title:    "Conformity assessment path",
			Article:  "Article 32",
			Status:   models.CRANA,
			Details:  "Cannot assess conformity requirements without a valid product category.",
			Severity: models.SeverityHigh,
		})
	} else if category == CategoryImportantClass2 || category == CategoryCritical {
		checks = append(checks, models.CRACheck{
			ID:          "CRA-CLASS-002",
			Title:       "Third-party conformity assessment",
			Article:     "Article 32",
			Status:      models.CRAWarn,
			Details:     "Product category " + category + " requires third-party conformity assessment. Verify this is planned.",
			Severity:    models.SeverityHigh,
			Remediation: "Engage a notified body for third-party conformity assessment as required by Article 32.",
		})
	} else if category == CategoryImportantClass1 {
		checks = append(checks, models.CRACheck{
			ID:       "CRA-CLASS-002",
			Title:    "Conformity assessment path",
			Article:  "Article 32",
			Status:   models.CRAPass,
			Details:  "Class I products can use internal conformity assessment when applying harmonised standards.",
			Severity: models.SeverityHigh,
		})
	} else if category == CategoryDefault {
		checks = append(checks, models.CRACheck{
			ID:       "CRA-CLASS-002",
			Title:    "Conformity assessment path",
			Article:  "Article 32",
			Status:   models.CRAPass,
			Details:  "Default category products can use internal conformity assessment.",
			Severity: models.SeverityHigh,
		})
	}

	return checks
}
