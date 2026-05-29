package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

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

func TestParseCVSSScore(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  float64
	}{
		{
			name:  "plain numeric 9.8",
			input: "9.8",
			want:  9.8,
		},
		{
			name:  "plain numeric 4.0",
			input: "4.0",
			want:  4.0,
		},
		{
			name:  "plain numeric 0.0",
			input: "0.0",
			want:  0.0,
		},
		{
			name:  "CVSS v3.1 critical vector",
			input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:  9.8,
		},
		{
			name:  "CVSS v3.1 high vector",
			input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			want:  6.1,
		},
		{
			name:  "CVSS v3.0 medium vector",
			input: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
			want:  5.5,
		},
		{
			name:  "empty string",
			input: "",
			want:  0,
		},
		{
			name:  "random garbage",
			input: "not a valid score",
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCVSSScore(tt.input)
			// Allow small floating point differences
			if diff := got - tt.want; diff < -0.01 || diff > 0.01 {
				t.Errorf("parseCVSSScore(%q) = %f, want %f", tt.input, got, tt.want)
			}
		})
	}
}

func TestCVSSToSeverity(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		want  string
	}{
		{"critical 9.8", 9.8, "CRITICAL"},
		{"critical 10.0", 10.0, "CRITICAL"},
		{"high 9.0", 9.0, "CRITICAL"},
		{"high 7.5", 7.5, "HIGH"},
		{"high 7.0", 7.0, "HIGH"},
		{"medium 6.9", 6.9, "MEDIUM"},
		{"medium 4.0", 4.0, "MEDIUM"},
		{"low 3.9", 3.9, "LOW"},
		{"low 0.1", 0.1, "LOW"},
		{"unknown 0.0", 0.0, "UNKNOWN"},
		{"unknown negative", -1.0, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cvssToSeverity(tt.score)
			if got != tt.want {
				t.Errorf("cvssToSeverity(%f) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestExtractSeverity(t *testing.T) {
	tests := []struct {
		name  string
		vuln  osvVulnerability
		want  string
	}{
		{
			name: "CVSS v3 numeric score",
			vuln: osvVulnerability{
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "9.8"}},
			},
			want: "CRITICAL",
		},
		{
			name: "CVSS v3 vector score",
			vuln: osvVulnerability{
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			},
			want: "CRITICAL",
		},
		{
			name: "CVSS v2 numeric score",
			vuln: osvVulnerability{
				Severity: []osvSeverity{{Type: "CVSS_V2", Score: "7.5"}},
			},
			want: "HIGH",
		},
		{
			name: "no severity",
			vuln: osvVulnerability{
				Severity: []osvSeverity{},
			},
			want: "UNKNOWN",
		},
		{
			name: "unknown severity type",
			vuln: osvVulnerability{
				Severity: []osvSeverity{{Type: "UNKNOWN", Score: "5.0"}},
			},
			want: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSeverity(tt.vuln)
			if got != tt.want {
				t.Errorf("extractSeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestQueryBatch_retriesTransientFailures(t *testing.T) {
	var mu sync.Mutex
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		currentAttempt := attempts
		mu.Unlock()

		// Return 503 twice, then 200
		if currentAttempt <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		resp := osvBatchResponse{
			Results: []osvBatchResult{{
				Vulns: []osvVulnerability{{
					ID:      "GHSA-retry-test",
					Summary: "Retry test vulnerability",
					Aliases: []string{"CVE-2024-0002"},
					Severity: []osvSeverity{{
						Type:  "CVSS_V3",
						Score: "7.5",
					}},
					Affected: []osvAffected{{
						Ranges: []osvRange{{
							Type: "SEMVER",
							Events: []osvEvent{
								{Introduced: "0"},
								{Fixed: "2.0.0"},
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
		Name:      "example.com/retry-test",
		Version:   "1.0.0",
		Ecosystem: models.EcosystemGo,
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := client.QueryBatch(ctx, components)
	if err != nil {
		t.Fatalf("QueryBatch returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	mu.Lock()
	defer mu.Unlock()
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}

	f := findings[0]
	if f.ID != "GHSA-retry-test" {
		t.Errorf("ID = %q, want %q", f.ID, "GHSA-retry-test")
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want %q", f.Severity, models.SeverityHigh)
	}
}

func TestQueryBatch_givesUpAfterMaxRetries(t *testing.T) {
	var mu sync.Mutex
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()

		// Always return 503
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	components := []models.Component{{
		Name:      "example.com/fail-test",
		Version:   "1.0.0",
		Ecosystem: models.EcosystemGo,
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.QueryBatch(ctx, components)
	if err == nil {
		t.Fatal("expected error after max retries, got nil")
	}

	mu.Lock()
	defer mu.Unlock()
	// Should attempt maxRetries + 1 times (0, 1, 2, 3)
	if attempts != maxRetries+1 {
		t.Errorf("expected %d attempts, got %d", maxRetries+1, attempts)
	}
}
