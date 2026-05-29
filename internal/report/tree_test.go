package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestWriteTree_basic(t *testing.T) {
	components := []models.Component{
		{
			Name:      "A",
			Version:   "1.0.0",
			Direct:    true,
			DependsOn: []string{"B@2.0.0"},
		},
		{
			Name:      "B",
			Version:   "2.0.0",
			Direct:    false,
			DependsOn: []string{"C@3.0.0"},
		},
		{
			Name:      "C",
			Version:   "3.0.0",
			Direct:    false,
			DependsOn: []string{},
		},
	}

	var buf bytes.Buffer
	err := WriteTree(&buf, components)
	if err != nil {
		t.Fatalf("WriteTree failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "A@1.0.0") {
		t.Errorf("output missing A@1.0.0: %s", output)
	}
	if !strings.Contains(output, "B@2.0.0") {
		t.Errorf("output missing B@2.0.0: %s", output)
	}
	if !strings.Contains(output, "C@3.0.0") {
		t.Errorf("output missing C@3.0.0: %s", output)
	}
	if !strings.Contains(output, "Dependency Tree (3 components)") {
		t.Errorf("output missing header: %s", output)
	}
}

func TestWriteTree_no_direct(t *testing.T) {
	components := []models.Component{
		{
			Name:      "A",
			Version:   "1.0.0",
			Direct:    false,
			DependsOn: []string{},
		},
		{
			Name:      "B",
			Version:   "2.0.0",
			Direct:    false,
			DependsOn: []string{},
		},
		{
			Name:      "C",
			Version:   "3.0.0",
			Direct:    false,
			DependsOn: []string{},
		},
	}

	var buf bytes.Buffer
	err := WriteTree(&buf, components)
	if err != nil {
		t.Fatalf("WriteTree failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "A@1.0.0") {
		t.Errorf("output missing A@1.0.0 in flat list: %s", output)
	}
	if !strings.Contains(output, "B@2.0.0") {
		t.Errorf("output missing B@2.0.0 in flat list: %s", output)
	}
}

func TestWriteTree_circular(t *testing.T) {
	components := []models.Component{
		{
			Name:      "A",
			Version:   "1.0.0",
			Direct:    true,
			DependsOn: []string{"B@2.0.0"},
		},
		{
			Name:      "B",
			Version:   "2.0.0",
			Direct:    false,
			DependsOn: []string{"A@1.0.0"},
		},
	}

	var buf bytes.Buffer
	err := WriteTree(&buf, components)
	if err != nil {
		t.Fatalf("WriteTree failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "(circular)") {
		t.Errorf("output should detect circular dependency: %s", output)
	}
}

func TestComputeTreeStats_basic(t *testing.T) {
	components := []models.Component{
		{Name: "A", Version: "1.0.0", Direct: true},
		{Name: "B", Version: "2.0.0", Direct: true},
		{Name: "C", Version: "3.0.0", Direct: false},
		{Name: "D", Version: "4.0.0", Direct: false},
		{Name: "E", Version: "5.0.0", Direct: false},
	}

	stats := ComputeTreeStats(components)

	if stats.TotalComponents != 5 {
		t.Errorf("expected 5 total components, got %d", stats.TotalComponents)
	}
	if stats.DirectDeps != 2 {
		t.Errorf("expected 2 direct deps, got %d", stats.DirectDeps)
	}
	if stats.TransitiveDeps != 3 {
		t.Errorf("expected 3 transitive deps, got %d", stats.TransitiveDeps)
	}
}

func TestComputeTreeStats_depth(t *testing.T) {
	components := []models.Component{
		{
			Name:      "A",
			Version:   "1.0.0",
			Direct:    true,
			DependsOn: []string{"B@2.0.0"},
		},
		{
			Name:      "B",
			Version:   "2.0.0",
			Direct:    false,
			DependsOn: []string{"C@3.0.0"},
		},
		{
			Name:      "C",
			Version:   "3.0.0",
			Direct:    false,
			DependsOn: []string{},
		},
	}

	stats := ComputeTreeStats(components)

	// Depth should be 2 (A at depth 0, B at depth 1, C at depth 2)
	if stats.MaxDepth != 2 {
		t.Errorf("expected max depth 2, got %d", stats.MaxDepth)
	}
}
