package hygiene

import (
	"strings"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestIsSHAPinned(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		// Valid SHA pins
		{"abc123def456abc123def456abc123def456abc1", true},
		{"0000000000000000000000000000000000000000", true},
		{"ffffffffffffffffffffffffffffffffffffffff", true},
		{"ABCDEF0123456789ABCDEF0123456789ABCDEF01", true},

		// Invalid: wrong length
		{"abc123def456abc123def456abc123def456", false},
		{"abc123def456abc123def456abc123def456abc12", false},
		{"", false},

		// Invalid: non-hex characters
		{"abc123def456abc123def456abc123def456abcg", false},
		{"abc123def456abc123def456abc123def456abc ", false},
		{"abc123def456abc123def456abc123def456abc-", false},

		// Version tags (not SHA)
		{"v4", false},
		{"v4.1.0", false},
		{"v1.2.3", false},
		{"main", false},
		{"master", false},
		{"latest", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := isSHAPinned(tt.version)
			if got != tt.want {
				t.Errorf("isSHAPinned(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"actions/checkout", "actions-checkout"},
		{"docker/build-push-action", "docker-build-push-action"},
		{"my.action@v1", "my-action-v1"},
		{"owner/repo/path@ref", "owner-repo-path-ref"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeID(tt.name)
			if got != tt.want {
				t.Errorf("sanitizeID(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestCheckActionSecurity_SHAPinned(t *testing.T) {
	components := []models.Component{
		{
			Name:      "actions/checkout",
			Version:   "abc123def456abc123def456abc123def456abc1",
			Ecosystem: models.EcosystemGitHubActions,
			PkgURL:    "pkg:githubactions/actions/checkout@abc123def456abc123def456abc123def456abc1",
		},
		{
			Name:      "docker/build-push-action",
			Version:   "0000000000000000000000000000000000000000",
			Ecosystem: models.EcosystemGitHubActions,
			PkgURL:    "pkg:githubactions/docker/build-push-action@0000000000000000000000000000000000000000",
		},
	}

	findings := CheckActionSecurity(components)
	if len(findings) != 0 {
		t.Errorf("SHA-pinned actions should have no findings, got %d: %v", len(findings), findings)
	}
}

func TestCheckActionSecurity_UnpinnedTag(t *testing.T) {
	components := []models.Component{
		{
			Name:      "actions/checkout",
			Version:   "v4",
			Ecosystem: models.EcosystemGitHubActions,
			PkgURL:    "pkg:githubactions/actions/checkout@v4",
		},
	}

	findings := CheckActionSecurity(components)
	if len(findings) != 1 {
		t.Errorf("unpinned tag should produce 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityMedium {
		t.Errorf("severity = %q, want %q", f.Severity, models.SeverityMedium)
	}
	if f.Source != "hygiene" {
		t.Errorf("source = %q, want %q", f.Source, "hygiene")
	}
	if !strings.Contains(f.Summary, "not pinned") {
		t.Errorf("summary should mention pinning: %q", f.Summary)
	}
}

func TestCheckActionSecurity_UnpinnedSemver(t *testing.T) {
	components := []models.Component{
		{
			Name:      "actions/setup-node",
			Version:   "v4.1.0",
			Ecosystem: models.EcosystemGitHubActions,
			PkgURL:    "pkg:githubactions/actions/setup-node@v4.1.0",
		},
	}

	findings := CheckActionSecurity(components)
	if len(findings) != 1 {
		t.Errorf("unpinned semver should produce 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityMedium {
		t.Errorf("severity = %q, want %q", f.Severity, models.SeverityMedium)
	}
}

func TestCheckActionSecurity_UnpinnedBranch(t *testing.T) {
	components := []models.Component{
		{
			Name:      "actions/setup-python",
			Version:   "main",
			Ecosystem: models.EcosystemGitHubActions,
			PkgURL:    "pkg:githubactions/actions/setup-python@main",
		},
	}

	findings := CheckActionSecurity(components)
	if len(findings) != 1 {
		t.Errorf("unpinned branch should produce 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityMedium {
		t.Errorf("severity = %q, want %q", f.Severity, models.SeverityMedium)
	}
}

func TestCheckActionSecurity_IgnoresNonGitHubActions(t *testing.T) {
	components := []models.Component{
		{
			Name:      "express",
			Version:   "4.18.0",
			Ecosystem: models.EcosystemNpm,
			PkgURL:    "pkg:npm/express@4.18.0",
		},
		{
			Name:      "github.com/spf13/cobra",
			Version:   "v1.8.0",
			Ecosystem: models.EcosystemGo,
			PkgURL:    "pkg:golang/github.com/spf13/cobra@v1.8.0",
		},
	}

	findings := CheckActionSecurity(components)
	if len(findings) != 0 {
		t.Errorf("non-GitHub-Actions components should be ignored, got %d findings", len(findings))
	}
}

func TestCheckActionSecurity_EmptyList(t *testing.T) {
	findings := CheckActionSecurity([]models.Component{})
	if len(findings) != 0 {
		t.Errorf("empty component list should produce no findings, got %d", len(findings))
	}
}

func TestCheckActionSecurity_MixedComponents(t *testing.T) {
	components := []models.Component{
		{
			Name:      "actions/checkout",
			Version:   "v4",
			Ecosystem: models.EcosystemGitHubActions,
			PkgURL:    "pkg:githubactions/actions/checkout@v4",
		},
		{
			Name:      "docker/build-push-action",
			Version:   "abc123def456abc123def456abc123def456abc1",
			Ecosystem: models.EcosystemGitHubActions,
			PkgURL:    "pkg:githubactions/docker/build-push-action@abc123def456abc123def456abc123def456abc1",
		},
		{
			Name:      "express",
			Version:   "4.18.0",
			Ecosystem: models.EcosystemNpm,
			PkgURL:    "pkg:npm/express@4.18.0",
		},
		{
			Name:      "actions/setup-python",
			Version:   "main",
			Ecosystem: models.EcosystemGitHubActions,
			PkgURL:    "pkg:githubactions/actions/setup-python@main",
		},
	}

	findings := CheckActionSecurity(components)
	// Should find 2 unpinned actions (checkout@v4 and setup-python@main)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings for unpinned actions, got %d", len(findings))
	}

	// Verify all findings are for GitHub Actions
	for _, f := range findings {
		if f.Component.Ecosystem != models.EcosystemGitHubActions {
			t.Errorf("finding component ecosystem = %q, want %q", f.Component.Ecosystem, models.EcosystemGitHubActions)
		}
	}
}

func TestCheckActionSecurity_FindingDetails(t *testing.T) {
	components := []models.Component{
		{
			Name:      "actions/checkout",
			Version:   "v4",
			Ecosystem: models.EcosystemGitHubActions,
			PkgURL:    "pkg:githubactions/actions/checkout@v4",
			Direct:    true,
		},
	}

	findings := CheckActionSecurity(components)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "ACTIONS-UNPIN-actions-checkout" {
		t.Errorf("ID = %q, want %q", f.ID, "ACTIONS-UNPIN-actions-checkout")
	}
	if f.Component.Name != "actions/checkout" {
		t.Errorf("component name = %q, want %q", f.Component.Name, "actions/checkout")
	}
	if f.Component.Version != "v4" {
		t.Errorf("component version = %q, want %q", f.Component.Version, "v4")
	}
	if !f.Component.Direct {
		t.Errorf("component direct = %v, want true", f.Component.Direct)
	}
	if !strings.Contains(f.Details, "mutable") {
		t.Errorf("details should mention mutability: %q", f.Details)
	}
}
