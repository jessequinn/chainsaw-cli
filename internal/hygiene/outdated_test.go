package hygiene

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestCheckOutdated_GoModuleBehind(t *testing.T) {
	// Mock Go proxy returning v5.0.0 when current is v2.0.0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/example.com/mylib/@latest" {
			resp := goLatestInfo{Version: "v5.0.0"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	components := []models.Component{
		{
			Name:      "example.com/mylib",
			Version:   "v2.0.0",
			Ecosystem: models.EcosystemGo,
			Direct:    true,
		},
	}

	cfg := OutdatedConfig{
		MajorThreshold:  2,
		BaseGoProxy:     srv.URL,
		BaseNPMRegistry: "https://registry.npmjs.org",
		HTTPClient:      http.DefaultClient,
	}

	findings := CheckOutdated(context.Background(), components, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityMedium {
		t.Errorf("severity = %q, want %q", f.Severity, models.SeverityMedium)
	}
	if f.Source != "outdated" {
		t.Errorf("source = %q, want %q", f.Source, "outdated")
	}
	if f.FixedIn != "v5.0.0" {
		t.Errorf("fixed_in = %q, want %q", f.FixedIn, "v5.0.0")
	}
}

func TestCheckOutdated_GoModuleCurrent(t *testing.T) {
	// Mock Go proxy returning v2.1.0 when current is v2.0.0 (less than threshold)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/example.com/mylib/@latest" {
			resp := goLatestInfo{Version: "v2.1.0"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	components := []models.Component{
		{
			Name:      "example.com/mylib",
			Version:   "v2.0.0",
			Ecosystem: models.EcosystemGo,
			Direct:    true,
		},
	}

	cfg := OutdatedConfig{
		MajorThreshold:  2,
		BaseGoProxy:     srv.URL,
		BaseNPMRegistry: "https://registry.npmjs.org",
		HTTPClient:      http.DefaultClient,
	}

	findings := CheckOutdated(context.Background(), components, cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (version not behind threshold), got %d", len(findings))
	}
}

func TestCheckOutdated_NPMPackageBehind(t *testing.T) {
	// Mock npm registry returning 8.0.0 when current is 5.0.0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lodash" {
			resp := npmPackageInfo{}
			resp.DistTags.Latest = "8.0.0"
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	components := []models.Component{
		{
			Name:      "lodash",
			Version:   "5.0.0",
			Ecosystem: models.EcosystemNpm,
			Direct:    true,
		},
	}

	cfg := OutdatedConfig{
		MajorThreshold:  2,
		BaseGoProxy:     "https://proxy.golang.org",
		BaseNPMRegistry: srv.URL,
		HTTPClient:      http.DefaultClient,
	}

	findings := CheckOutdated(context.Background(), components, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityMedium {
		t.Errorf("severity = %q, want %q", f.Severity, models.SeverityMedium)
	}
	if f.FixedIn != "8.0.0" {
		t.Errorf("fixed_in = %q, want %q", f.FixedIn, "8.0.0")
	}
}

func TestCheckOutdated_SkipIndirectDependencies(t *testing.T) {
	// Indirect dependencies should not be checked
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should not be called for indirect dependencies
		t.Error("HTTP request made for indirect dependency - should be skipped")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	components := []models.Component{
		{
			Name:      "example.com/indirect",
			Version:   "v1.0.0",
			Ecosystem: models.EcosystemGo,
			Direct:    false, // indirect
		},
	}

	cfg := OutdatedConfig{
		MajorThreshold:  2,
		BaseGoProxy:     srv.URL,
		BaseNPMRegistry: srv.URL,
		HTTPClient:      http.DefaultClient,
	}

	findings := CheckOutdated(context.Background(), components, cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for indirect dependencies, got %d", len(findings))
	}
}

func TestCheckOutdated_RegistryError(t *testing.T) {
	// Registry returning 404 should not crash, just skip
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	components := []models.Component{
		{
			Name:      "example.com/missing",
			Version:   "v1.0.0",
			Ecosystem: models.EcosystemGo,
			Direct:    true,
		},
	}

	cfg := OutdatedConfig{
		MajorThreshold:  2,
		BaseGoProxy:     srv.URL,
		BaseNPMRegistry: srv.URL,
		HTTPClient:      http.DefaultClient,
	}

	findings := CheckOutdated(context.Background(), components, cfg)
	// Should gracefully degrade and return no findings
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on registry error, got %d", len(findings))
	}
}

func TestCheckOutdated_UnsupportedEcosystem(t *testing.T) {
	// Unsupported ecosystems should be skipped gracefully
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP request made for unsupported ecosystem - should be skipped")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	components := []models.Component{
		{
			Name:      "some-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemDocker, // unsupported
			Direct:    true,
		},
	}

	cfg := OutdatedConfig{
		MajorThreshold:  2,
		BaseGoProxy:     srv.URL,
		BaseNPMRegistry: srv.URL,
		HTTPClient:      http.DefaultClient,
	}

	findings := CheckOutdated(context.Background(), components, cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unsupported ecosystem, got %d", len(findings))
	}
}

func TestCheckOutdated_SameVersion(t *testing.T) {
	// If current version matches latest, no finding
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/example.com/current/@latest" {
			resp := goLatestInfo{Version: "v1.2.3"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	components := []models.Component{
		{
			Name:      "example.com/current",
			Version:   "v1.2.3",
			Ecosystem: models.EcosystemGo,
			Direct:    true,
		},
	}

	cfg := OutdatedConfig{
		MajorThreshold:  2,
		BaseGoProxy:     srv.URL,
		BaseNPMRegistry: "https://registry.npmjs.org",
		HTTPClient:      http.DefaultClient,
	}

	findings := CheckOutdated(context.Background(), components, cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when versions match, got %d", len(findings))
	}
}

func TestCheckOutdated_ThresholdExactly(t *testing.T) {
	// When major version gap equals threshold exactly, should report finding
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/example.com/lib/@latest" {
			resp := goLatestInfo{Version: "v5.0.0"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	components := []models.Component{
		{
			Name:      "example.com/lib",
			Version:   "v3.0.0",
			Ecosystem: models.EcosystemGo,
			Direct:    true,
		},
	}

	cfg := OutdatedConfig{
		MajorThreshold:  2, // gap is exactly 2
		BaseGoProxy:     srv.URL,
		BaseNPMRegistry: "https://registry.npmjs.org",
		HTTPClient:      http.DefaultClient,
	}

	findings := CheckOutdated(context.Background(), components, cfg)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding when gap equals threshold, got %d", len(findings))
	}
}

func TestParseMajor(t *testing.T) {
	tests := []struct {
		version string
		want    int
	}{
		{"v1.2.3", 1},
		{"1.2.3", 1},
		{"v2.0.0", 2},
		{"2.0.0", 2},
		{"0.9.1", 0},
		{"v0.1.0", 0},
		{"", 0},
		{"invalid", 0},
		{"v-1.0.0", 0},
		{"10.5.2", 10},
		{"v100.0.0", 100},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := parseMajor(tt.version)
			if got != tt.want {
				t.Errorf("parseMajor(%q) = %d, want %d", tt.version, got, tt.want)
			}
		})
	}
}

func TestCheckOutdated_DefaultConfig(t *testing.T) {
	// Test that DefaultOutdatedConfig provides sensible defaults
	cfg := DefaultOutdatedConfig()
	if cfg.MajorThreshold != 2 {
		t.Errorf("default MajorThreshold = %d, want 2", cfg.MajorThreshold)
	}
	if cfg.BaseGoProxy == "" {
		t.Error("default BaseGoProxy is empty")
	}
	if cfg.BaseNPMRegistry == "" {
		t.Error("default BaseNPMRegistry is empty")
	}
	if cfg.HTTPClient == nil {
		t.Error("default HTTPClient is nil")
	}
}

func TestCheckOutdated_MultipleComponents(t *testing.T) {
	// Test with multiple components, some direct and some indirect
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lib1/@latest" {
			resp := goLatestInfo{Version: "v5.0.0"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		if r.URL.Path == "/lib2/@latest" {
			resp := goLatestInfo{Version: "v3.0.0"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	components := []models.Component{
		{
			Name:      "lib1",
			Version:   "v2.0.0",
			Ecosystem: models.EcosystemGo,
			Direct:    true, // behind by 3 major versions
		},
		{
			Name:      "lib2",
			Version:   "v1.0.0",
			Ecosystem: models.EcosystemGo,
			Direct:    false, // indirect - should be skipped
		},
	}

	cfg := OutdatedConfig{
		MajorThreshold:  2,
		BaseGoProxy:     srv.URL,
		BaseNPMRegistry: "https://registry.npmjs.org",
		HTTPClient:      http.DefaultClient,
	}

	findings := CheckOutdated(context.Background(), components, cfg)
	// Should only find lib1 (indirect lib2 is skipped)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Component.Name != "lib1" {
		t.Errorf("finding component = %q, want %q", findings[0].Component.Name, "lib1")
	}
}
