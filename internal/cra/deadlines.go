package cra

import (
	"fmt"
	"time"
)

// CRADeadline represents a CRA regulation milestone.
type CRADeadline struct {
	Date        time.Time `json:"date"`
	Article     string    `json:"article"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Applies     []string  `json:"applies_to"` // product categories this applies to
}

// Urgency returns the urgency level based on days remaining.
func (d CRADeadline) Urgency(now time.Time) string {
	days := int(d.Date.Sub(now).Hours() / 24)
	switch {
	case days < 0:
		return "OVERDUE"
	case days <= 30:
		return "RED"
	case days <= 90:
		return "YELLOW"
	default:
		return "green"
	}
}

// DaysRemaining returns days until the deadline (negative if past).
func (d CRADeadline) DaysRemaining(now time.Time) int {
	return int(d.Date.Sub(now).Hours() / 24)
}

// AllDeadlines returns the complete CRA timeline.
func AllDeadlines() []CRADeadline {
	return []CRADeadline{
		{
			Date:        time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC),
			Article:     "Article 35(1)",
			Title:       "Notified Body framework activation",
			Description: "Member States designate Notified Bodies for conformity assessment",
			Applies:     []string{"important-class-1", "important-class-2", "critical"},
		},
		{
			Date:        time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
			Article:     "EN 40000",
			Title:       "Harmonised standards target publication",
			Description: "CEN/CENELEC EN 40000 harmonised standards expected (may slip to Q1 2027)",
			Applies:     []string{"default", "important-class-1", "important-class-2", "critical"},
		},
		{
			Date:        time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC),
			Article:     "Article 14",
			Title:       "Vulnerability reporting obligations",
			Description: "24-hour early warning, 72-hour detailed notification, 14-day final report via ENISA SRP",
			Applies:     []string{"default", "important-class-1", "important-class-2", "critical"},
		},
		{
			Date:        time.Date(2026, 12, 11, 0, 0, 0, 0, time.UTC),
			Article:     "Article 35(2)",
			Title:       "Notified Body availability target",
			Description: "Commission target for sufficient Notified Body capacity",
			Applies:     []string{"important-class-1", "important-class-2", "critical"},
		},
		{
			Date:        time.Date(2027, 12, 11, 0, 0, 0, 0, time.UTC),
			Article:     "Article 69",
			Title:       "Full CRA application",
			Description: "All Annex I essential requirements enforced; conformity assessment required; CE marking mandatory",
			Applies:     []string{"default", "important-class-1", "important-class-2", "critical"},
		},
	}
}

// FilterByCategory returns deadlines applicable to the given product category.
func FilterByCategory(category string) []CRADeadline {
	if category == "" {
		category = "default"
	}
	var result []CRADeadline
	for _, d := range AllDeadlines() {
		for _, c := range d.Applies {
			if c == category {
				result = append(result, d)
				break
			}
		}
	}
	return result
}

// FormatDeadlineTable returns a formatted string showing all applicable deadlines.
func FormatDeadlineTable(category string, now time.Time) string {
	deadlines := FilterByCategory(category)
	var result string
	result += "CRA Compliance Timeline:\n"
	for _, d := range deadlines {
		days := d.DaysRemaining(now)
		urgency := d.Urgency(now)
		var status string
		if days < 0 {
			status = fmt.Sprintf("OVERDUE by %d days", -days)
		} else {
			status = fmt.Sprintf("%d days remaining [%s]", days, urgency)
		}
		result += fmt.Sprintf("  %s  %-45s %s  %s\n", d.Date.Format("2006-01-02"), d.Title, d.Article, status)
	}
	return result
}
