package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chainsaw-dev/chainsaw/internal/analysis"
	"github.com/chainsaw-dev/chainsaw/internal/cra"
	"github.com/chainsaw-dev/chainsaw/internal/hygiene"
	"github.com/chainsaw-dev/chainsaw/internal/initcmd"
	"github.com/chainsaw-dev/chainsaw/internal/policy"
	"github.com/chainsaw-dev/chainsaw/internal/report"
	"github.com/chainsaw-dev/chainsaw/internal/sbom"
	"github.com/chainsaw-dev/chainsaw/internal/scanner"
	"github.com/chainsaw-dev/chainsaw/internal/vuln"
	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(2)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "chainsaw",
		Short: "Supply chain security scanner for CRA compliance",
		Long:  "Chainsaw scans dependency trees and lockfiles to surface vulnerabilities, licence violations, typosquatting, and lockfile integrity issues.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(scanCmd())
	root.AddCommand(sbomCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(complyCmd())
	root.AddCommand(supplyChainCmd())
	root.AddCommand(initSecurityCmd())
	root.AddCommand(initCICmd())

	return root
}

func initCICmd() *cobra.Command {
	var (
		goVersion  string
		failOn     string
		policyPath string
		ecosystems string
	)

	cmd := &cobra.Command{
		Use:   "init-ci [path]",
		Short: "Generate GitHub Actions workflow for supply chain scanning",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			cfg := initcmd.DefaultCIConfig()
			if cmd.Flags().Changed("go-version") {
				cfg.GoVersion = goVersion
			}
			if cmd.Flags().Changed("fail-on") {
				cfg.FailOn = failOn
			}
			if cmd.Flags().Changed("policy") {
				cfg.PolicyPath = policyPath
			}
			if cmd.Flags().Changed("ecosystems") {
				cfg.Ecosystems = ecosystems
			}

			written, err := initcmd.WriteCIFiles(root, cfg)
			if err != nil {
				return fmt.Errorf("writing CI workflow: %w", err)
			}

			fmt.Fprintln(os.Stdout, "Created CI workflow:")
			for _, f := range written {
				fmt.Fprintf(os.Stdout, "  %s\n", f)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&goVersion, "go-version", "1.22", "Go version for the workflow")
	cmd.Flags().StringVar(&failOn, "fail-on", "HIGH", "Minimum severity to fail on")
	cmd.Flags().StringVar(&policyPath, "policy", ".chainsaw.yaml", "Path to policy file")
	cmd.Flags().StringVar(&ecosystems, "ecosystems", "", "Comma-separated ecosystems to scan")

	return cmd
}

func scanCmd() *cobra.Command {
	var (
		format     string
		failOn     string
		ecosystem  string
		policyPath string
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan dependencies for vulnerabilities and hygiene issues",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			// Load policy.
			pol, err := loadPolicy(ctx, policyPath)
			if err != nil {
				return err
			}

			// Override fail-on from flag if set explicitly.
			if cmd.Flags().Changed("fail-on") {
				pol.FailOn = models.ParseSeverity(failOn)
			}

			// Resolve scanners, optionally filtered by ecosystem.
			scanners := resolveScanners(ecosystem)
			if len(scanners) == 0 {
				return fmt.Errorf("no scanners registered for ecosystems: %s", ecosystem)
			}

		// Detect and parse dependencies.
		var components []models.Component
		for _, s := range scanners {
			manifests, err := s.DetectManifests(ctx, root)
			if err != nil {
				return fmt.Errorf("detecting manifests (%s): %w", s.Ecosystem(), err)
			}
			for _, m := range manifests {
				deps, err := s.ParseDependencies(ctx, m)
				if err != nil {
					return fmt.Errorf("parsing %s: %w", m, err)
				}
				components = append(components, deps...)
			}
		}

			// Vulnerability matching.
			client := vuln.NewClient()
			matcher := vuln.NewMatcher(client)
			findings, err := matcher.Match(ctx, components)
			if err != nil {
				return fmt.Errorf("vulnerability matching: %w", err)
			}

			// Hygiene checks.
			var hygieneFindings []models.Finding
			hygieneFindings = append(hygieneFindings, hygiene.CheckTyposquatting(components)...)
			hygieneFindings = append(hygieneFindings, hygiene.CheckIntegrity(components)...)

			result := models.ScanResult{
				Components:  components,
				Findings:    findings,
				Hygiene:     hygieneFindings,
				Timestamp:   time.Now(),
				ToolVersion: version,
			}

			// Evaluate policy.
			_, exitCode := pol.Evaluate(result)

			// Output.
			if err := writeOutput(ctx, os.Stdout, format, result); err != nil {
				return err
			}

			if exitCode != 0 {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json, sarif")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Minimum severity to fail on (CRITICAL, HIGH, MEDIUM, LOW)")
	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", "Comma-separated ecosystems to scan (e.g. go,npm)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to .chainsaw.yaml policy file")

	return cmd
}

func sbomCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "sbom [path]",
		Short: "Generate a software bill of materials",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

		components, err := scanner.DetectAll(ctx, root)
		if err != nil {
			return fmt.Errorf("detecting dependencies: %w", err)
		}

			switch format {
			case "cyclonedx":
				data, err := sbom.GenerateCycloneDX(components, version)
				if err != nil {
					return fmt.Errorf("generating CycloneDX SBOM: %w", err)
				}
				_, err = os.Stdout.Write(data)
				if err != nil {
					return fmt.Errorf("writing SBOM: %w", err)
				}
				fmt.Fprintln(os.Stdout)
			default:
				return fmt.Errorf("unsupported SBOM format: %s", format)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "cyclonedx", "SBOM format: cyclonedx")

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("chainsaw %s\n", version)
		},
	}
}

func complyCmd() *cobra.Command {
	var (
		format     string
		policyPath string
	)

	cmd := &cobra.Command{
		Use:   "comply [path]",
		Short: "Assess CRA compliance posture",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

		// Load policy to check for CRA config.
		pol, err := loadPolicy(ctx, policyPath)
		if err != nil {
			return err
		}

		craConfig := &cra.CRAConfig{}

		// Detect and parse all dependencies.
		scanners := resolveScanners("")
		var components []models.Component
		for _, s := range scanners {
			manifests, err := s.DetectManifests(ctx, root)
			if err != nil {
				return fmt.Errorf("detecting manifests (%s): %w", s.Ecosystem(), err)
			}
			for _, m := range manifests {
				deps, err := s.ParseDependencies(ctx, m)
				if err != nil {
					return fmt.Errorf("parsing %s: %w", m, err)
				}
				components = append(components, deps...)
			}
		}

			// Vulnerability matching.
			client := vuln.NewClient()
			matcher := vuln.NewMatcher(client)
			findings, err := matcher.Match(ctx, components)
			if err != nil {
				return fmt.Errorf("vulnerability matching: %w", err)
			}

			// Hygiene checks.
			var hygieneFindings []models.Finding
			hygieneFindings = append(hygieneFindings, hygiene.CheckTyposquatting(components)...)
			hygieneFindings = append(hygieneFindings, hygiene.CheckIntegrity(components)...)

			// Build assessment context and run CRA checks.
			assessCtx := cra.AssessmentContext{
				RootPath:    root,
				Components:  components,
				Findings:    findings,
				Hygiene:     hygieneFindings,
				ToolVersion: version,
				Config:      craConfig,
			}
			result := cra.Assess(ctx, &assessCtx)

			// Evaluate CRA result against policy.
			pass, reason := pol.EvaluateCRA(result)
			if !pass {
				fmt.Fprintf(os.Stderr, "Policy violation: %s\n", reason)
			}

			// Output.
			switch format {
			case "json":
				return cra.WriteComplianceJSON(ctx, os.Stdout, result)
			default:
				return cra.WriteComplianceReport(ctx, os.Stdout, result)
			}
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to .chainsaw.yaml policy file")

	return cmd
}

func supplyChainCmd() *cobra.Command {
	var (
		format     string
		policyPath string
	)

	cmd := &cobra.Command{
		Use:   "supply-chain [path]",
		Short: "Analyse supply chain pinning and blast radius",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

		// Load policy.
		pol, err := loadPolicy(ctx, policyPath)
		if err != nil {
			return err
		}

		// Detect and parse all dependencies.
		scanners := resolveScanners("")
		var components []models.Component
		for _, s := range scanners {
			manifests, err := s.DetectManifests(ctx, root)
			if err != nil {
				return fmt.Errorf("detecting manifests (%s): %w", s.Ecosystem(), err)
			}
			for _, m := range manifests {
				deps, err := s.ParseDependencies(ctx, m)
				if err != nil {
					return fmt.Errorf("parsing %s: %w", m, err)
				}
				components = append(components, deps...)
			}
		}

		// Enrich each component with supply chain metadata.
		var enriched []models.InfraComponent
		for _, c := range components {
			enriched = append(enriched, analysis.EnrichComponent(c))
		}

			// Calculate pinning score and blast radius.
			pinningScore := analysis.CalculatePinningScore(enriched)
			blastRadii := analysis.AssessAll(enriched)

			result := models.SupplyChainResult{
				Components:   enriched,
				PinningScore: pinningScore,
				BlastRadii:   blastRadii,
				Timestamp:    time.Now(),
				ToolVersion:  version,
			}

			// Evaluate supply chain result against policy.
			pass, reason := pol.EvaluateSupplyChain(result)
			if !pass {
				fmt.Fprintf(os.Stderr, "Policy violation: %s\n", reason)
			}

			// Output.
			switch format {
			case "json":
				return analysis.WriteSupplyChainJSON(ctx, os.Stdout, result)
			default:
				return analysis.WriteSupplyChainReport(ctx, os.Stdout, result)
			}
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to .chainsaw.yaml policy file")

	return cmd
}

func loadPolicy(ctx context.Context, path string) (*policy.Policy, error) {
	if path != "" {
		return policy.LoadPolicy(ctx, path)
	}
	// Try default policy file.
	if _, err := os.Stat(".chainsaw.yaml"); err == nil {
		return policy.LoadPolicy(ctx, ".chainsaw.yaml")
	}
	return policy.DefaultPolicy(), nil
}

func resolveScanners(ecosystemFlag string) []scanner.Scanner {
	if ecosystemFlag == "" {
		return scanner.GetAll()
	}

	ecos := strings.Split(ecosystemFlag, ",")
	var out []scanner.Scanner
	for _, e := range ecos {
		eco := models.Ecosystem(strings.TrimSpace(e))
		if s, ok := scanner.GetByEcosystem(eco); ok {
			out = append(out, s)
		}
	}
	return out
}

func initSecurityCmd() *cobra.Command {
	var (
		org            string
		email          string
		supportEndDate string
		csirtContact   string
		nonInteractive bool
	)

	cmd := &cobra.Command{
		Use:   "init-security [path]",
		Short: "Scaffold security policy files for CRA compliance",
		Long:  "Generate SECURITY.md, .well-known/security.txt, and .chainsaw.yaml with CRA metadata.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = nonInteractive // v1: always non-interactive

			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			cfg := initcmd.DefaultSecurityConfig()
			if org != "" {
				cfg.OrgName = org
				cfg.Manufacturer = org
			}
			if email != "" {
				cfg.SecurityEmail = email
			}
			if supportEndDate != "" {
				cfg.SupportEndDate = supportEndDate
			}
			if csirtContact != "" {
				cfg.CSIRTContact = csirtContact
			}

			written, err := initcmd.WriteSecurityFiles(root, cfg)
			if err != nil {
				return fmt.Errorf("writing security files: %w", err)
			}

			fmt.Fprintln(os.Stdout, "Created security policy files:")
			for _, f := range written {
				fmt.Fprintf(os.Stdout, "  %s\n", f)
			}
			fmt.Fprintln(os.Stdout, "\nReview TODO markers in the generated files before committing.")

			return nil
		},
	}

	cmd.Flags().StringVar(&org, "org", "", "Organization name")
	cmd.Flags().StringVar(&email, "email", "", "Security contact email")
	cmd.Flags().StringVar(&supportEndDate, "support-end-date", "", "Support end date (YYYY-MM-DD)")
	cmd.Flags().StringVar(&csirtContact, "csirt-contact", "", "CSIRT contact email")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "Skip prompts, use defaults and flags")

	return cmd
}

func writeOutput(ctx context.Context, w *os.File, format string, result models.ScanResult) error {
	switch format {
	case "table":
		return report.WriteTable(ctx, w, result)
	case "json":
		return report.WriteJSON(ctx, w, result)
	case "sarif":
		return report.WriteSARIF(ctx, w, result)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}
