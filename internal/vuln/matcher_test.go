package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestMatcher_Match_Deduplication(t *testing.T) {
	// Server returns the same vuln twice for the same component.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dup := osvVulnerability{ID: "GHSA-DUP1", Summary: "dup"}
		resp := osvBatchResponse{
			Results: []osvBatchResult{{
				Vulns: []osvVulnerability{dup, dup},
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	matcher := NewMatcher(client)

	findings, err := matcher.Match(context.Background(), []models.Component{{
		Name: "lodash", Version: "4.17.0", Ecosystem: models.EcosystemNpm,
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(findings))
	}
}

func TestMatcher_Match_SeveritySorting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := osvBatchResponse{
			Results: []osvBatchResult{{
				Vulns: []osvVulnerability{
					{ID: "LOW-1", Summary: "low", Severity: []osvSeverity{{Type: "CVSS_V3", Score: "2.0"}}},
					{ID: "CRIT-1", Summary: "critical", Severity: []osvSeverity{{Type: "CVSS_V3", Score: "9.5"}}},
					{ID: "MED-1", Summary: "medium", Severity: []osvSeverity{{Type: "CVSS_V3", Score: "5.0"}}},
				},
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	matcher := NewMatcher(client)

	findings, err := matcher.Match(context.Background(), []models.Component{{
		Name: "express", Version: "4.0.0", Ecosystem: models.EcosystemNpm,
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("first finding severity = %q, want CRITICAL", findings[0].Severity)
	}
	if findings[1].Severity != models.SeverityMedium {
		t.Errorf("second finding severity = %q, want MEDIUM", findings[1].Severity)
	}
	if findings[2].Severity != models.SeverityLow {
		t.Errorf("third finding severity = %q, want LOW", findings[2].Severity)
	}
}

func TestMatcher_Match_EmptyComponents(t *testing.T) {
	client := NewClient()
	matcher := NewMatcher(client)

	findings, err := matcher.Match(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
