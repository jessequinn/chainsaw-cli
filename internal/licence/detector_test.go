package licence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestDetectNpm_MockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/express/4.18.2" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"license": "MIT"})
	}))
	defer srv.Close()

	d := NewDetector()
	d.NpmBaseURL = srv.URL

	lic, err := d.detectNpm(context.Background(), "express", "4.18.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lic != "MIT" {
		t.Fatalf("expected MIT, got %s", lic)
	}
}

func TestDetectPyPI_MockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pypi/requests/2.31.0/json" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"info": map[string]interface{}{"license": "Apache-2.0"},
		})
	}))
	defer srv.Close()

	d := NewDetector()
	d.PyPIBaseURL = srv.URL

	lic, err := d.detectPyPI(context.Background(), "requests", "2.31.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lic != "Apache-2.0" {
		t.Fatalf("expected Apache-2.0, got %s", lic)
	}
}

func TestDetectAll_MixedEcosystems(t *testing.T) {
	npmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"license": "MIT"})
	}))
	defer npmSrv.Close()

	pypiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"info": map[string]interface{}{"license": "BSD-3-Clause"},
		})
	}))
	defer pypiSrv.Close()

	d := NewDetector()
	d.NpmBaseURL = npmSrv.URL
	d.PyPIBaseURL = pypiSrv.URL

	components := []models.Component{
		{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm},
		{Name: "requests", Version: "2.31.0", Ecosystem: models.EcosystemPyPI},
		{Name: "golang.org/x/mod", Version: "0.14.0", Ecosystem: models.EcosystemGo},
	}

	detected, _ := d.DetectAll(context.Background(), components)

	if detected != 2 {
		t.Fatalf("expected 2 detected, got %d", detected)
	}
	if components[0].Licenses[0] != "MIT" {
		t.Errorf("npm: expected MIT, got %s", components[0].Licenses[0])
	}
	if components[1].Licenses[0] != "BSD-3-Clause" {
		t.Errorf("pypi: expected BSD-3-Clause, got %s", components[1].Licenses[0])
	}
	if components[2].Licenses[0] != "unknown" {
		t.Errorf("go: expected unknown, got %s", components[2].Licenses[0])
	}
}

func TestDetectAll_CachesResults(t *testing.T) {
	var callCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)
		json.NewEncoder(w).Encode(map[string]interface{}{"license": "MIT"})
	}))
	defer srv.Close()

	d := NewDetector()
	d.NpmBaseURL = srv.URL

	components := []models.Component{
		{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm},
		{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm},
	}

	d.DetectAll(context.Background(), components)

	if atomic.LoadInt64(&callCount) != 1 {
		t.Fatalf("expected 1 HTTP call, got %d", atomic.LoadInt64(&callCount))
	}
}

func TestEvaluateLicences_DenyMode(t *testing.T) {
	components := []models.Component{
		{Name: "pkg", Version: "1.0.0", Licenses: []string{"GPL-3.0"}},
	}
	findings := EvaluateLicences(components, "deny", nil, []string{"GPL-3.0"})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Source != "licence" {
		t.Errorf("expected source licence, got %s", findings[0].Source)
	}
}

func TestEvaluateLicences_AllowMode(t *testing.T) {
	components := []models.Component{
		{Name: "pkg", Version: "1.0.0", Licenses: []string{"AGPL-3.0"}},
	}
	findings := EvaluateLicences(components, "allow", []string{"MIT", "Apache-2.0"}, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	want := fmt.Sprintf("LICENCE-%s-%s", "pkg", "AGPL-3.0")
	if findings[0].ID != want {
		t.Errorf("expected ID %s, got %s", want, findings[0].ID)
	}
}

func TestEvaluateLicences_UnknownSkipped(t *testing.T) {
	components := []models.Component{
		{Name: "pkg", Version: "1.0.0", Licenses: []string{"unknown"}},
	}
	findings := EvaluateLicences(components, "allow", []string{"MIT"}, nil)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unknown licence in allow mode, got %d", len(findings))
	}
}
