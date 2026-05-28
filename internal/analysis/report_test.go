package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func sampleSupplyChainResult() models.SupplyChainResult {
	components := []models.InfraComponent{
		{Component: models.Component{Name: "actions/checkout", Version: "v4", Ecosystem: models.EcosystemGitHubActions}, PinType: models.PinVersionTag, SourceTrust: models.TrustOfficial, Layer: "ci-cd"},
		{Component: models.Component{Name: "library/golang", Version: "1.22", Ecosystem: models.EcosystemDocker}, PinType: models.PinVersionTag, SourceTrust: models.TrustOfficial, Layer: "infrastructure"},
		{Component: models.Component{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm}, PinType: models.PinVersionTag, SourceTrust: models.TrustCommunity, Layer: "application"},
	}
	blastRadii := []models.BlastRadius{
		{Component: components[0], Scope: "build-only", SecretsAccess: true, Score: 60},
		{Component: components[1], Scope: "runtime", Score: 30},
	}
	return models.SupplyChainResult{
		Components:   components,
		PinningScore: 70,
		BlastRadii:   blastRadii,
		Timestamp:    time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		ToolVersion:  "0.1.0",
	}
}

func TestWriteSupplyChainReport(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSupplyChainReport(context.Background(), &buf, sampleSupplyChainResult())
	if err != nil {
		t.Fatalf("WriteSupplyChainReport error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Supply Chain Analysis", "Pinning score: 70/100", "PIN TYPE"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestWriteSupplyChainJSON(t *testing.T) {
	var buf bytes.Buffer
	err := WriteSupplyChainJSON(context.Background(), &buf, sampleSupplyChainResult())
	if err != nil {
		t.Fatalf("WriteSupplyChainJSON error: %v", err)
	}

	var parsed models.SupplyChainResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.PinningScore != 70 {
		t.Errorf("PinningScore = %d, want 70", parsed.PinningScore)
	}
	if len(parsed.Components) != 3 {
		t.Errorf("Components count = %d, want 3", len(parsed.Components))
	}
}
