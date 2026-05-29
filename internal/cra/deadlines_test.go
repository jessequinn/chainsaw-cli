package cra

import (
	"strings"
	"testing"
	"time"
)

func TestAllDeadlines_returns_five_deadlines(t *testing.T) {
	deadlines := AllDeadlines()
	if len(deadlines) != 5 {
		t.Fatalf("expected 5 deadlines, got %d", len(deadlines))
	}
}

func TestFilterByCategory_default(t *testing.T) {
	deadlines := FilterByCategory("default")
	if len(deadlines) != 3 {
		t.Fatalf("expected 3 deadlines for default category, got %d", len(deadlines))
	}
	// Verify the titles are correct for default category
	titles := make(map[string]bool)
	for _, d := range deadlines {
		titles[d.Title] = true
	}
	expected := map[string]bool{
		"Harmonised standards target publication": true,
		"Vulnerability reporting obligations":     true,
		"Full CRA application":                    true,
	}
	if len(titles) != len(expected) {
		t.Fatalf("unexpected titles for default category")
	}
	for title := range expected {
		if !titles[title] {
			t.Errorf("missing expected title: %s", title)
		}
	}
}

func TestFilterByCategory_critical(t *testing.T) {
	deadlines := FilterByCategory("critical")
	if len(deadlines) != 5 {
		t.Fatalf("expected 5 deadlines for critical category, got %d", len(deadlines))
	}
}

func TestCRADeadline_Urgency(t *testing.T) {
	tests := []struct {
		name     string
		deadline CRADeadline
		now      time.Time
		expected string
	}{
		{
			name: "OVERDUE",
			deadline: CRADeadline{
				Date: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			expected: "OVERDUE",
		},
		{
			name: "RED - exactly 30 days",
			deadline: CRADeadline{
				Date: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			expected: "RED",
		},
		{
			name: "RED - 15 days",
			deadline: CRADeadline{
				Date: time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			expected: "RED",
		},
		{
			name: "YELLOW - exactly 90 days",
			deadline: CRADeadline{
				Date: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			expected: "YELLOW",
		},
		{
			name: "YELLOW - 60 days",
			deadline: CRADeadline{
				Date: time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			expected: "YELLOW",
		},
		{
			name: "green - more than 90 days",
			deadline: CRADeadline{
				Date: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			expected: "green",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.deadline.Urgency(tt.now)
			if got != tt.expected {
				t.Errorf("Urgency() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestCRADeadline_DaysRemaining(t *testing.T) {
	tests := []struct {
		name     string
		deadline CRADeadline
		now      time.Time
		expected int
	}{
		{
			name: "30 days remaining",
			deadline: CRADeadline{
				Date: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			expected: 30,
		},
		{
			name: "15 days remaining",
			deadline: CRADeadline{
				Date: time.Date(2026, 2, 16, 0, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			expected: 15,
		},
		{
			name: "negative - 10 days overdue",
			deadline: CRADeadline{
				Date: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
			expected: -10,
		},
		{
			name: "0 days - deadline is today",
			deadline: CRADeadline{
				Date: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.deadline.DaysRemaining(tt.now)
			if got != tt.expected {
				t.Errorf("DaysRemaining() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestFormatDeadlineTable_contains_dates(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	table := FormatDeadlineTable("critical", now)

	if !strings.Contains(table, "CRA Compliance Timeline") {
		t.Error("FormatDeadlineTable() should contain 'CRA Compliance Timeline'")
	}

	if !strings.Contains(table, "2026-06-11") {
		t.Error("FormatDeadlineTable() should contain first deadline date 2026-06-11")
	}

	if !strings.Contains(table, "2027-12-11") {
		t.Error("FormatDeadlineTable() should contain last deadline date 2027-12-11")
	}

	if !strings.Contains(table, "Article") {
		t.Error("FormatDeadlineTable() should contain article references")
	}

	if !strings.Contains(table, "days remaining") {
		t.Error("FormatDeadlineTable() should contain days remaining")
	}
}
