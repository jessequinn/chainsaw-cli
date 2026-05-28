package cra

import (
	"context"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// Checker is the interface for individual CRA compliance checks.
type Checker interface {
	Check(ctx *AssessmentContext) []models.CRACheck
}

// AssessmentContext holds all information needed for CRA checks.
type AssessmentContext struct {
	RootPath    string
	Components  []models.Component
	Findings    []models.Finding
	Hygiene     []models.Finding
	ToolVersion string
	Config      *CRAConfig
}

// CRAConfig holds CRA-specific configuration from .chainsaw.yaml.
type CRAConfig struct {
	ProductName     string `yaml:"product-name"`
	ProductVersion  string `yaml:"product-version"`
	Manufacturer    string `yaml:"manufacturer"`
	SupportEndDate  string `yaml:"support-end-date"`
	SecurityContact string `yaml:"security-contact"`
	DisclosureURL   string `yaml:"disclosure-policy-url"`
	CSIRTContact    string `yaml:"csirt-contact"`
	ProductCategory string `yaml:"product-category"`
}

// Assess runs all CRA compliance checks and returns the aggregated result.
func Assess(_ context.Context, actx *AssessmentContext) models.CRAResult {
	checkers := []Checker{
		&SBOMChecker{},
		&VulnChecker{},
		&DisclosureChecker{},
		&UpdateChecker{},
		&SupportChecker{},
		&ReportingChecker{},
	}

	var checks []models.CRACheck
	for _, c := range checkers {
		checks = append(checks, c.Check(actx)...)
	}

	passing := 0
	total := 0
	for _, ch := range checks {
		if ch.Status == models.CRANA {
			continue
		}
		total++
		if ch.Status == models.CRAPass {
			passing++
		}
	}

	score := 0
	if total > 0 {
		score = (passing * 100) / total
	}

	productName := "unknown"
	productVersion := ""
	if actx.Config != nil {
		if actx.Config.ProductName != "" {
			productName = actx.Config.ProductName
		}
		productVersion = actx.Config.ProductVersion
	}

	return models.CRAResult{
		ProductName:  productName,
		Version:      productVersion,
		Date:         time.Now().UTC(),
		Regulation:   "EU Cyber Resilience Act (Regulation (EU) 2024/2847)",
		OverallScore: score,
		Checks:       checks,
		NextDeadline: "2026-09-11",
		NextDeadDesc: "Article 14 reporting obligations",
	}
}
