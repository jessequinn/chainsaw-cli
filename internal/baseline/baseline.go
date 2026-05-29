package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

const DefaultFile = ".chainsaw-baseline.json"

// Baseline stores the known finding IDs for a project.
type Baseline struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	FindingIDs []string `json:"finding_ids"`
	HygieneIDs []string `json:"hygiene_ids"`
	Total     int       `json:"total"`
}

// Save writes the baseline to the given directory.
func Save(dir string, scanResult models.ScanResult) error {
	b := Baseline{
		Version:   "1.0",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	for _, f := range scanResult.Findings {
		b.FindingIDs = append(b.FindingIDs, f.ID)
	}
	for _, f := range scanResult.Hygiene {
		b.HygieneIDs = append(b.HygieneIDs, f.ID)
	}
	b.Total = len(b.FindingIDs) + len(b.HygieneIDs)

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}

	path := filepath.Join(dir, DefaultFile)
	return os.WriteFile(path, data, 0644)
}

// Load reads an existing baseline from the given directory.
// Returns nil, nil if no baseline file exists.
func Load(dir string) (*Baseline, error) {
	path := filepath.Join(dir, DefaultFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading baseline: %w", err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	return &b, nil
}

// FilterNew returns only findings NOT in the baseline.
// Also returns the count of baselined (suppressed) findings.
func FilterNew(findings []models.Finding, b *Baseline) (newFindings []models.Finding, baselinedCount int) {
	if b == nil {
		return findings, 0
	}

	known := make(map[string]bool, len(b.FindingIDs)+len(b.HygieneIDs))
	for _, id := range b.FindingIDs {
		known[id] = true
	}
	for _, id := range b.HygieneIDs {
		known[id] = true
	}

	for _, f := range findings {
		if known[f.ID] {
			baselinedCount++
		} else {
			newFindings = append(newFindings, f)
		}
	}
	return newFindings, baselinedCount
}

// Update refreshes an existing baseline, keeping the original CreatedAt.
func Update(dir string, scanResult models.ScanResult) error {
	existing, _ := Load(dir)

	b := Baseline{
		Version:   "1.0",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if existing != nil {
		b.CreatedAt = existing.CreatedAt
	}

	for _, f := range scanResult.Findings {
		b.FindingIDs = append(b.FindingIDs, f.ID)
	}
	for _, f := range scanResult.Hygiene {
		b.HygieneIDs = append(b.HygieneIDs, f.ID)
	}
	b.Total = len(b.FindingIDs) + len(b.HygieneIDs)

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}

	path := filepath.Join(dir, DefaultFile)
	return os.WriteFile(path, data, 0644)
}
