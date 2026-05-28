package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestMapEcosystem(t *testing.T) {
	t.Helper()
	tests := []struct {
		input models.Ecosystem
		want  string
	}{
		{"go", "Go"},
		{"npm", "npm"},
		{"pypi", "PyPI"},
		{"hex", "Hex"},
		{"maven", "Maven"},
		{"nuget", "NuGet"},
		{"crates.io", "crates.io"},
		{"rubygems", "RubyGems"},
		{"docker", ""},
		{"terraform", ""},
		{"unknown", ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			got := mapEcosystem(tt.input)
			if got != tt.want {
				t.Errorf("mapEcosystem(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func newTestClient(url string) *Client {
	return &Client{
		httpClient: http.DefaultClient,
		baseURL:    url,
	}
}

func TestQueryBatch_MockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := osvBatchResponse{
			Results: []osvBatchResult{{
				Vulns: []osvVulnerability{{
					ID:      "GHSA-1234",
					Summary: "Test vulnerability",
					Aliases: []string{"CVE-2024-0001"},
					Severity: []osvSeverity{{
						Type:  "CVSS_V3",
						Score: "9.8",
					}},
					Affected: []osvAffected{{
						Ranges: []osvRange{{
							Type: "SEMVER",
							Events: []osvEvent{
								{Introduced: "0"},
								{Fixed: "1.2.3"},
							},
						}},
					}},
					References: []osvReference{{
						Type: "ADVISORY",
						URL:  "https://example.com/advisory",
					}},
				}},
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	components := []models.Component{{
		Name:      "example.com/foo",
		Version:   "1.0.0",
		Ecosystem: models.EcosystemGo,
	}}

	findings, err := client.QueryBatch(context.Background(), components)
	if err != nil {
		t.Fatalf("QueryBatch returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "GHSA-1234" {
		t.Errorf("ID = %q, want %q", f.ID, "GHSA-1234")
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want %q", f.Severity, models.SeverityCritical)
	}
	if f.Component.Name != "example.com/foo" {
		t.Errorf("Component.Name = %q, want %q", f.Component.Name, "example.com/foo")
	}
	if f.FixedIn != "1.2.3" {
		t.Errorf("FixedIn = %q, want %q", f.FixedIn, "1.2.3")
	}
	if f.Source != "osv" {
		t.Errorf("Source = %q, want %q", f.Source, "osv")
	}
}

func TestQueryBatch_EmptyComponents(t *testing.T) {
	client := NewClient()
	findings, err := client.QueryBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestQueryBatch_SkipsUnknownEcosystems(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(osvBatchResponse{})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	components := []models.Component{
		{Name: "ubuntu", Version: "22.04", Ecosystem: models.EcosystemDocker},
		{Name: "hashicorp/aws", Version: "5.0.0", Ecosystem: models.EcosystemTerraform},
	}

	findings, err := client.QueryBatch(context.Background(), components)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
	if called {
		t.Error("server should not have been called for unknown ecosystems")
	}
}

func TestQueryBatch_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	components := []models.Component{{
		Name:      "lodash",
		Version:   "4.17.0",
		Ecosystem: models.EcosystemNpm,
	}}

	_, err := client.QueryBatch(context.Background(), components)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}
