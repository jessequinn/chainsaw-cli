package cra

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestCheckCSIRTContact_WithContact(t *testing.T) {
	config := &CRAConfig{
		CSIRTContact: "csirt@example.com",
	}
	check := checkCSIRTContact(config)

	if check.Status != models.CRAPass {
		t.Errorf("status = %q, want %q", check.Status, models.CRAPass)
	}
	if check.ID != "reporting-csirt" {
		t.Errorf("ID = %q, want %q", check.ID, "reporting-csirt")
	}
}

func TestCheckCSIRTContact_NoContact(t *testing.T) {
	config := &CRAConfig{
		CSIRTContact: "",
	}
	check := checkCSIRTContact(config)

	if check.Status != models.CRAFail {
		t.Errorf("status = %q, want %q", check.Status, models.CRAFail)
	}
	if check.Remediation == "" {
		t.Error("expected remediation for failed check")
	}
}

func TestCheckCSIRTContact_NilConfig(t *testing.T) {
	check := checkCSIRTContact(nil)

	if check.Status != models.CRAFail {
		t.Errorf("status = %q, want %q", check.Status, models.CRAFail)
	}
}

func TestCheckSecurityContact_WithContact(t *testing.T) {
	config := &CRAConfig{
		SecurityContact: "security@example.com",
	}
	check := checkSecurityContact(config)

	if check.Status != models.CRAPass {
		t.Errorf("status = %q, want %q", check.Status, models.CRAPass)
	}
	if check.ID != "reporting-security-contact" {
		t.Errorf("ID = %q, want %q", check.ID, "reporting-security-contact")
	}
}

func TestCheckSecurityContact_NoContact(t *testing.T) {
	config := &CRAConfig{
		SecurityContact: "",
	}
	check := checkSecurityContact(config)

	if check.Status != models.CRAFail {
		t.Errorf("status = %q, want %q", check.Status, models.CRAFail)
	}
}

func TestCheckSecurityContact_NilConfig(t *testing.T) {
	check := checkSecurityContact(nil)

	if check.Status != models.CRAFail {
		t.Errorf("status = %q, want %q", check.Status, models.CRAFail)
	}
}

func TestCheckIncidentResponseDoc_FileExists_WithKeywords(t *testing.T) {
	dir := t.TempDir()
	content := "# Security Policy\n\nIncident Response:\nPlease report security issues to security@example.com.\n"
	if err := os.WriteFile(filepath.Join(dir, "SECURITY.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	check := checkIncidentResponseDoc(dir)

	if check.Status != models.CRAPass {
		t.Errorf("status = %q, want %q", check.Status, models.CRAPass)
	}
	if check.ID != "reporting-incident-response" {
		t.Errorf("ID = %q, want %q", check.ID, "reporting-incident-response")
	}
}

func TestCheckIncidentResponseDoc_FileExists_NoKeywords(t *testing.T) {
	dir := t.TempDir()
	content := "# Security Policy\n\nPlease contact security@example.com for questions.\n"
	if err := os.WriteFile(filepath.Join(dir, "SECURITY.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	check := checkIncidentResponseDoc(dir)

	if check.Status != models.CRAWarn {
		t.Errorf("status = %q, want %q", check.Status, models.CRAWarn)
	}
}

func TestCheckIncidentResponseDoc_FileExists_WithReport(t *testing.T) {
	dir := t.TempDir()
	content := "# Security Policy\n\nTo report a vulnerability, please email security@example.com.\n"
	if err := os.WriteFile(filepath.Join(dir, "SECURITY.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	check := checkIncidentResponseDoc(dir)

	if check.Status != models.CRAPass {
		t.Errorf("status = %q, want %q", check.Status, models.CRAPass)
	}
}

func TestCheckIncidentResponseDoc_FileNotExists(t *testing.T) {
	dir := t.TempDir()

	check := checkIncidentResponseDoc(dir)

	if check.Status != models.CRAFail {
		t.Errorf("status = %q, want %q", check.Status, models.CRAFail)
	}
	if check.Remediation == "" {
		t.Error("expected remediation for failed check")
	}
}

func TestCheckIncidentResponseDoc_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	content := "# Security Policy\n\nINCIDENT RESPONSE PROCEDURES:\nPlease contact security@example.com.\n"
	if err := os.WriteFile(filepath.Join(dir, "SECURITY.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	check := checkIncidentResponseDoc(dir)

	if check.Status != models.CRAPass {
		t.Errorf("status = %q, want %q", check.Status, models.CRAPass)
	}
}

func TestCheckSecurityTxt_FileExists(t *testing.T) {
	dir := t.TempDir()
	wellKnownDir := filepath.Join(dir, ".well-known")
	if err := os.MkdirAll(wellKnownDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "Contact: security@example.com\nExpires: 2025-12-31T23:59:59.000Z\n"
	if err := os.WriteFile(filepath.Join(wellKnownDir, "security.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	check := checkSecurityTxt(dir)

	if check.Status != models.CRAPass {
		t.Errorf("status = %q, want %q", check.Status, models.CRAPass)
	}
	if check.ID != "reporting-security-txt" {
		t.Errorf("ID = %q, want %q", check.ID, "reporting-security-txt")
	}
}

func TestCheckSecurityTxt_FileNotExists(t *testing.T) {
	dir := t.TempDir()

	check := checkSecurityTxt(dir)

	if check.Status != models.CRAFail {
		t.Errorf("status = %q, want %q", check.Status, models.CRAFail)
	}
	if check.Remediation == "" {
		t.Error("expected remediation for failed check")
	}
}

func TestCheckIncidentResponsePlaybook_FileExists_WithCRATimelines(t *testing.T) {
	dir := t.TempDir()
	content := "# Incident Response Playbook\n\nCRA Article 14 Reporting:\n- 24 hours: Early warning\n- 72 hours: Notification\n- 14 days: Final report\n"
	if err := os.WriteFile(filepath.Join(dir, "INCIDENT-RESPONSE.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	check := checkIncidentResponsePlaybook(dir)

	if check.Status != models.CRAPass {
		t.Errorf("status = %q, want %q", check.Status, models.CRAPass)
	}
	if check.ID != "reporting-incident-playbook" {
		t.Errorf("ID = %q, want %q", check.ID, "reporting-incident-playbook")
	}
}

func TestCheckIncidentResponsePlaybook_FileExists_NoTimelines(t *testing.T) {
	dir := t.TempDir()
	content := "# Incident Response Playbook\n\nCRA Article 14 Reporting:\nPlease contact security@example.com.\n"
	if err := os.WriteFile(filepath.Join(dir, "INCIDENT-RESPONSE.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	check := checkIncidentResponsePlaybook(dir)

	if check.Status != models.CRAWarn {
		t.Errorf("status = %q, want %q", check.Status, models.CRAWarn)
	}
}

func TestCheckIncidentResponsePlaybook_FileNotExists(t *testing.T) {
	dir := t.TempDir()

	check := checkIncidentResponsePlaybook(dir)

	if check.Status != models.CRAFail {
		t.Errorf("status = %q, want %q", check.Status, models.CRAFail)
	}
	if check.Remediation == "" {
		t.Error("expected remediation for failed check")
	}
}

func TestCheck24HourProcess_WithCSIRTContact(t *testing.T) {
	config := &CRAConfig{
		CSIRTContact: "csirt@example.com",
	}
	check := check24HourProcess(config)

	if check.Status != models.CRAPass {
		t.Errorf("status = %q, want %q", check.Status, models.CRAPass)
	}
	if check.ID != "reporting-24h-process" {
		t.Errorf("ID = %q, want %q", check.ID, "reporting-24h-process")
	}
}

func TestCheck24HourProcess_NoCSIRTContact(t *testing.T) {
	config := &CRAConfig{
		CSIRTContact: "",
	}
	check := check24HourProcess(config)

	if check.Status != models.CRAWarn {
		t.Errorf("status = %q, want %q", check.Status, models.CRAWarn)
	}
}

func TestCheck24HourProcess_NilConfig(t *testing.T) {
	check := check24HourProcess(nil)

	if check.Status != models.CRAWarn {
		t.Errorf("status = %q, want %q", check.Status, models.CRAWarn)
	}
}

func TestReportingChecker_FullConfig(t *testing.T) {
	dir := t.TempDir()

	// Create SECURITY.md with keywords
	securityContent := "# Security Policy\n\nIncident Response:\nPlease report to security@example.com.\n"
	if err := os.WriteFile(filepath.Join(dir, "SECURITY.md"), []byte(securityContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create .well-known/security.txt
	wellKnownDir := filepath.Join(dir, ".well-known")
	if err := os.MkdirAll(wellKnownDir, 0o755); err != nil {
		t.Fatal(err)
	}
	securityTxtContent := "Contact: security@example.com\n"
	if err := os.WriteFile(filepath.Join(wellKnownDir, "security.txt"), []byte(securityTxtContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create INCIDENT-RESPONSE.md with CRA timelines
	incidentContent := "# Incident Response Playbook\n\nCRA Article 14:\n- 24 hours: Early warning\n- 72 hours: Notification\n- 14 days: Final report\n"
	if err := os.WriteFile(filepath.Join(dir, "INCIDENT-RESPONSE.md"), []byte(incidentContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create CI workflow
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wfContent := "name: CI\non: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: chainsaw\n"
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(wfContent), 0o644); err != nil {
		t.Fatal(err)
	}

	config := &CRAConfig{
		CSIRTContact:    "csirt@example.com",
		SecurityContact: "security@example.com",
	}

	checker := &ReportingChecker{}
	actx := &AssessmentContext{
		RootPath: dir,
		Config:   config,
	}

	checks := checker.Check(actx)

	// Should have 7 checks: CI scanning, CSIRT, Security contact, Incident response, Security.txt, Incident playbook, 24h process
	if len(checks) != 7 {
		t.Errorf("check count = %d, want 7", len(checks))
	}

	// Verify each check
	checkMap := make(map[string]models.CRACheck)
	for _, ch := range checks {
		checkMap[ch.ID] = ch
	}

	expectedPasses := []string{
		"reporting-ci-scanning",
		"reporting-csirt",
		"reporting-security-contact",
		"reporting-incident-response",
		"reporting-security-txt",
		"reporting-incident-playbook",
		"reporting-24h-process",
	}

	for _, id := range expectedPasses {
		ch, ok := checkMap[id]
		if !ok {
			t.Errorf("check %q not found", id)
			continue
		}
		if ch.Status != models.CRAPass {
			t.Errorf("check %q status = %q, want %q", id, ch.Status, models.CRAPass)
		}
	}
}

func TestReportingChecker_MinimalConfig(t *testing.T) {
	dir := t.TempDir()

	checker := &ReportingChecker{}
	actx := &AssessmentContext{
		RootPath: dir,
		Config:   nil,
	}

	checks := checker.Check(actx)

	if len(checks) != 7 {
		t.Errorf("check count = %d, want 7", len(checks))
	}

	// Verify failures
	checkMap := make(map[string]models.CRACheck)
	for _, ch := range checks {
		checkMap[ch.ID] = ch
	}

	expectedFails := []string{
		"reporting-csirt",
		"reporting-security-contact",
		"reporting-incident-response",
		"reporting-security-txt",
		"reporting-incident-playbook",
	}

	for _, id := range expectedFails {
		ch, ok := checkMap[id]
		if !ok {
			t.Errorf("check %q not found", id)
			continue
		}
		if ch.Status != models.CRAFail {
			t.Errorf("check %q status = %q, want %q", id, ch.Status, models.CRAFail)
		}
	}

	// 24h process should warn
	if ch, ok := checkMap["reporting-24h-process"]; ok {
		if ch.Status != models.CRAWarn {
			t.Errorf("check reporting-24h-process status = %q, want %q", ch.Status, models.CRAWarn)
		}
	}
}

func TestReportingChecker_PartialConfig(t *testing.T) {
	dir := t.TempDir()

	// Create SECURITY.md without keywords
	securityContent := "# Security Policy\n\nPlease contact security@example.com.\n"
	if err := os.WriteFile(filepath.Join(dir, "SECURITY.md"), []byte(securityContent), 0o644); err != nil {
		t.Fatal(err)
	}

	config := &CRAConfig{
		CSIRTContact: "csirt@example.com",
		// SecurityContact is empty
	}

	checker := &ReportingChecker{}
	actx := &AssessmentContext{
		RootPath: dir,
		Config:   config,
	}

	checks := checker.Check(actx)

	checkMap := make(map[string]models.CRACheck)
	for _, ch := range checks {
		checkMap[ch.ID] = ch
	}

	// CSIRT should pass
	if ch, ok := checkMap["reporting-csirt"]; ok {
		if ch.Status != models.CRAPass {
			t.Errorf("check reporting-csirt status = %q, want %q", ch.Status, models.CRAPass)
		}
	}

	// Security contact should fail
	if ch, ok := checkMap["reporting-security-contact"]; ok {
		if ch.Status != models.CRAFail {
			t.Errorf("check reporting-security-contact status = %q, want %q", ch.Status, models.CRAFail)
		}
	}

	// Incident response should warn (file exists but no keywords)
	if ch, ok := checkMap["reporting-incident-response"]; ok {
		if ch.Status != models.CRAWarn {
			t.Errorf("check reporting-incident-response status = %q, want %q", ch.Status, models.CRAWarn)
		}
	}

	// Incident playbook should fail (file doesn't exist)
	if ch, ok := checkMap["reporting-incident-playbook"]; ok {
		if ch.Status != models.CRAFail {
			t.Errorf("check reporting-incident-playbook status = %q, want %q", ch.Status, models.CRAFail)
		}
	}

	// 24h process should pass (CSIRT is set)
	if ch, ok := checkMap["reporting-24h-process"]; ok {
		if ch.Status != models.CRAPass {
			t.Errorf("check reporting-24h-process status = %q, want %q", ch.Status, models.CRAPass)
		}
	}
}
