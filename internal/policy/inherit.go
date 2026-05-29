package policy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

const maxInheritDepth = 3

// loadPolicyWithInheritance resolves the extends chain and merges policies.
func loadPolicyWithInheritance(ctx context.Context, path string, depth int) (*Policy, error) {
	if depth > maxInheritDepth {
		return nil, fmt.Errorf("policy inheritance depth exceeds maximum of %d", maxInheritDepth)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var pf policyFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&pf); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}

	// Validate raw fail-on value before normalization.
	// ParseSeverity silently maps unknown values to NONE, so we must
	// reject typos like "HIHG" here rather than letting them become NONE.
	if raw := pf.Policy.FailOn; raw != "" {
		normalised := models.ParseSeverity(string(raw))
		if normalised == models.SeverityNone && strings.ToUpper(string(raw)) != string(models.SeverityNone) {
			return nil, fmt.Errorf("invalid policy: invalid fail_on severity %q: must be CRITICAL, HIGH, MEDIUM, or LOW", raw)
		}
	}

	// Build local policy.
	local := buildPolicy(pf)

	// If no parent, return local directly.
	if pf.Extends == "" {
		if err := local.validate(); err != nil {
			return nil, fmt.Errorf("invalid policy: %w", err)
		}
		return local, nil
	}

	// Resolve parent.
	var parent *Policy
	if strings.HasPrefix(pf.Extends, "http://") || strings.HasPrefix(pf.Extends, "https://") {
		parent, err = loadRemotePolicy(ctx, pf.Extends, depth+1)
	} else {
		// Resolve relative to the current policy file's directory.
		parentPath := pf.Extends
		if !filepath.IsAbs(parentPath) {
			parentPath = filepath.Join(filepath.Dir(path), parentPath)
		}
		parent, err = loadPolicyWithInheritance(ctx, parentPath, depth+1)
	}
	if err != nil {
		return nil, fmt.Errorf("loading parent policy %q: %w", pf.Extends, err)
	}

	// Merge: local overrides parent.
	merged := mergePolicy(parent, local)
	if err := merged.validate(); err != nil {
		return nil, fmt.Errorf("invalid merged policy: %w", err)
	}
	return merged, nil
}

func loadRemotePolicy(ctx context.Context, url string, depth int) (*Policy, error) {
	if depth > maxInheritDepth {
		return nil, fmt.Errorf("remote policy inheritance depth exceeds maximum of %d", maxInheritDepth)
	}

	httpCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(httpCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching remote policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote policy returned HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var pf policyFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&pf); err != nil {
		return nil, fmt.Errorf("parsing remote policy: %w", err)
	}

	// Remote policies cannot extend further to keep complexity bounded.
	if pf.Extends != "" {
		return nil, fmt.Errorf("remote policy cannot extend another policy (nested extends not supported)")
	}

	p := buildPolicy(pf)
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("invalid remote policy: %w", err)
	}
	return p, nil
}

func buildPolicy(pf policyFile) *Policy {
	// Normalize ecosystem overrides.
	normalizedEcosystems := make(map[string]EcosystemOverride)
	for key, override := range pf.Policy.Ecosystems {
		if override.FailOn != "" {
			normalizedEcosystems[key] = EcosystemOverride{
				FailOn: models.ParseSeverity(string(override.FailOn)),
			}
		}
	}

	p := &Policy{
		FailOn:      models.ParseSeverity(string(pf.Policy.FailOn)),
		Ignore:      pf.Policy.Ignore,
		Ecosystems:  normalizedEcosystems,
		CRA:         pf.CRA,
		SupplyChain: pf.SupplyChain,
	}

	// Licences can appear either under policy: or at the top level.
	// Top-level takes precedence if both are set.
	if len(pf.Licences.DenyList) > 0 || len(pf.Licences.AllowList) > 0 || pf.Licences.Mode != "" {
		p.Licences = pf.Licences
	} else {
		p.Licences = pf.Policy.Licences
	}

	return p
}

// mergePolicy merges parent and child, with child fields taking precedence when set.
func mergePolicy(parent, child *Policy) *Policy {
	merged := &Policy{}

	// FailOn: child overrides if set.
	if child.FailOn != "" && child.FailOn != models.SeverityNone {
		merged.FailOn = child.FailOn
	} else {
		merged.FailOn = parent.FailOn
	}

	// Ignore: combine both lists (deduplicate by ID).
	seen := make(map[string]bool)
	for _, r := range parent.Ignore {
		if !seen[r.ID] {
			merged.Ignore = append(merged.Ignore, r)
			seen[r.ID] = true
		}
	}
	for _, r := range child.Ignore {
		if !seen[r.ID] {
			merged.Ignore = append(merged.Ignore, r)
			seen[r.ID] = true
		}
	}

	// CRA: child overrides if any field is set.
	merged.CRA = parent.CRA
	if child.CRA.RequiredScore > 0 {
		merged.CRA.RequiredScore = child.CRA.RequiredScore
	}
	if child.CRA.Manufacturer != "" {
		merged.CRA.Manufacturer = child.CRA.Manufacturer
	}
	if child.CRA.SecurityContact != "" {
		merged.CRA.SecurityContact = child.CRA.SecurityContact
	}
	if child.CRA.SupportEndDate != "" {
		merged.CRA.SupportEndDate = child.CRA.SupportEndDate
	}
	if child.CRA.CSIRTContact != "" {
		merged.CRA.CSIRTContact = child.CRA.CSIRTContact
	}

	// SupplyChain: child overrides if any field is set.
	merged.SupplyChain = parent.SupplyChain
	if child.SupplyChain.MinPinningScore > 0 {
		merged.SupplyChain.MinPinningScore = child.SupplyChain.MinPinningScore
	}
	if child.SupplyChain.RequireSHAPins {
		merged.SupplyChain.RequireSHAPins = true
	}

	// Licences: child overrides entirely if set.
	if child.Licences.Mode != "" || len(child.Licences.DenyList) > 0 || len(child.Licences.AllowList) > 0 {
		merged.Licences = child.Licences
	} else {
		merged.Licences = parent.Licences
	}

	// Ecosystems: merge maps, child overrides per key.
	merged.Ecosystems = make(map[string]EcosystemOverride)
	for k, v := range parent.Ecosystems {
		merged.Ecosystems[k] = v
	}
	for k, v := range child.Ecosystems {
		merged.Ecosystems[k] = v
	}

	return merged
}
