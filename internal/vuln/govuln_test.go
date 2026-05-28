package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestGoVulnClient_QueryModule_MockServer(t *testing.T) {
	moduleIndex := []goVulnModuleEntry{
		{ID: "GO-2024-0001", Aliases: []string{"CVE-2024-0001"}},
	}
	vulnDetail := goVulnDetail{
		ID:      "GO-2024-0001",
		Aliases: []string{"CVE-2024-0001"},
		Summary: "Test vulnerability",
		Details: "A test vuln",
		Affected: []goVulnAffected{
			{
				Package: goVulnPackage{Name: "github.com/example/mod", Ecosystem: "Go"},
				Ranges: []osvRange{
					{
						Type: "SEMVER",
						Events: []osvEvent{
							{Introduced: "0"},
							{Fixed: "1.2.3"},
						},
					},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index/modules/github.com/example/mod.json":
			json.NewEncoder(w).Encode(moduleIndex)
		case "/ID/GO-2024-0001.json":
			json.NewEncoder(w).Encode(vulnDetail)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &GoVulnClient{client: srv.Client(), baseURL: srv.URL}
	comp := models.Component{
		Name:      "github.com/example/mod",
		Version:   "1.0.0",
		Ecosystem: models.EcosystemGo,
	}

	findings, err := client.QueryModule(context.Background(), comp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "GO-2024-0001" {
		t.Errorf("expected ID GO-2024-0001, got %s", f.ID)
	}
	if f.Source != "govulndb" {
		t.Errorf("expected source govulndb, got %s", f.Source)
	}
	if f.FixedIn != "1.2.3" {
		t.Errorf("expected fixedIn 1.2.3, got %s", f.FixedIn)
	}
	if f.Summary != "Test vulnerability" {
		t.Errorf("expected summary 'Test vulnerability', got %s", f.Summary)
	}
}

func TestGoVulnClient_QueryModule_NoVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &GoVulnClient{client: srv.Client(), baseURL: srv.URL}
	comp := models.Component{
		Name:      "github.com/safe/mod",
		Version:   "1.0.0",
		Ecosystem: models.EcosystemGo,
	}

	findings, err := client.QueryModule(context.Background(), comp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestGoVulnClient_QueryAll_FiltersToGo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only Go module should be queried; npm should not reach the server.
		if r.URL.Path == "/index/modules/github.com/example/mod.json" {
			json.NewEncoder(w).Encode([]goVulnModuleEntry{})
			return
		}
		t.Errorf("unexpected request to %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &GoVulnClient{client: srv.Client(), baseURL: srv.URL}
	components := []models.Component{
		{Name: "github.com/example/mod", Version: "1.0.0", Ecosystem: models.EcosystemGo},
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm},
	}

	findings, err := client.QueryAll(context.Background(), components)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestGoVulnClient_QueryAll_Empty(t *testing.T) {
	requestMade := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMade = true
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &GoVulnClient{client: srv.Client(), baseURL: srv.URL}
	components := []models.Component{
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm},
		{Name: "express", Version: "4.18.0", Ecosystem: models.EcosystemNpm},
	}

	findings, err := client.QueryAll(context.Background(), components)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	if requestMade {
		t.Error("expected no HTTP requests for non-Go components")
	}
}

func TestGoVulnClient_NotAffected_VersionAboveFixed(t *testing.T) {
	moduleIndex := []goVulnModuleEntry{
		{ID: "GO-2024-0001"},
	}
	vulnDetail := goVulnDetail{
		ID:      "GO-2024-0001",
		Summary: "Fixed vuln",
		Affected: []goVulnAffected{
			{
				Package: goVulnPackage{Name: "github.com/example/mod", Ecosystem: "Go"},
				Ranges: []osvRange{
					{
						Type: "SEMVER",
						Events: []osvEvent{
							{Introduced: "0"},
							{Fixed: "1.2.3"},
						},
					},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index/modules/github.com/example/mod.json":
			json.NewEncoder(w).Encode(moduleIndex)
		case "/ID/GO-2024-0001.json":
			json.NewEncoder(w).Encode(vulnDetail)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &GoVulnClient{client: srv.Client(), baseURL: srv.URL}
	comp := models.Component{
		Name:      "github.com/example/mod",
		Version:   "2.0.0",
		Ecosystem: models.EcosystemGo,
	}

	findings, err := client.QueryModule(context.Background(), comp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for version above fixed, got %d", len(findings))
	}
}

func TestMatchesRange(t *testing.T) {
	events := []osvEvent{
		{Introduced: "0"},
		{Fixed: "1.5.0"},
	}

	tests := []struct {
		version  string
		affected bool
	}{
		{"v1.0.0", true},
		{"v1.4.9", true},
		{"v1.5.0", false},
		{"v2.0.0", false},
	}

	for _, tt := range tests {
		got := matchesRange(tt.version, events)
		if got != tt.affected {
			t.Errorf("matchesRange(%s) = %v, want %v", tt.version, got, tt.affected)
		}
	}
}
