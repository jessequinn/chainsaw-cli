package trend

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

const historyDir = ".chainsaw/history"

// TrendEntry is a stored compliance assessment result.
type TrendEntry struct {
	Date         time.Time `json:"date"`
	OverallScore int       `json:"overall_score"`
	PassCount    int       `json:"pass_count"`
	FailCount    int       `json:"fail_count"`
	WarnCount    int       `json:"warn_count"`
	TotalChecks  int       `json:"total_checks"`
}

// SaveResult stores a CRA assessment result to the history directory.
func SaveResult(rootPath string, result models.CRAResult) error {
	dir := filepath.Join(rootPath, historyDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating history directory: %w", err)
	}

	entry := toEntry(result)
	filename := fmt.Sprintf("cra-%s.json", entry.Date.Format("2006-01-02T150405"))
	path := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling trend entry: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// LoadHistory loads all trend entries from the history directory, sorted by date.
func LoadHistory(rootPath string) ([]TrendEntry, error) {
	dir := filepath.Join(rootPath, historyDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading history directory: %w", err)
	}

	var history []TrendEntry
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var entry TrendEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		history = append(history, entry)
	}

	sort.Slice(history, func(i, j int) bool {
		return history[i].Date.Before(history[j].Date)
	})

	return history, nil
}

// FormatTrend returns a human-readable trend summary.
func FormatTrend(history []TrendEntry, current TrendEntry) string {
	if len(history) == 0 {
		return fmt.Sprintf("CRA Score: %d%% (first assessment, no trend data)", current.OverallScore)
	}

	prev := history[len(history)-1]
	delta := current.OverallScore - prev.OverallScore

	direction := "unchanged"
	if delta > 0 {
		direction = fmt.Sprintf("+%d%% improvement", delta)
	} else if delta < 0 {
		direction = fmt.Sprintf("%d%% regression", delta)
	}

	return fmt.Sprintf("CRA Score: %d%% (%s since %s)",
		current.OverallScore, direction, prev.Date.Format("2006-01-02"))
}

func toEntry(result models.CRAResult) TrendEntry {
	pass, fail, warn := 0, 0, 0
	for _, c := range result.Checks {
		switch c.Status {
		case models.CRAPass:
			pass++
		case models.CRAFail:
			fail++
		case models.CRAWarn:
			warn++
		}
	}
	return TrendEntry{
		Date:         result.Date,
		OverallScore: result.OverallScore,
		PassCount:    pass,
		FailCount:    fail,
		WarnCount:    warn,
		TotalChecks:  len(result.Checks),
	}
}
