package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/chainsaw-dev/chainsaw/internal/analysis"
	"github.com/chainsaw-dev/chainsaw/internal/cra"
	"github.com/chainsaw-dev/chainsaw/internal/diff"
	"github.com/chainsaw-dev/chainsaw/internal/engine"
	"github.com/chainsaw-dev/chainsaw/internal/evidence"
	"github.com/chainsaw-dev/chainsaw/internal/hygiene"
	"github.com/chainsaw-dev/chainsaw/internal/licence"
	"github.com/chainsaw-dev/chainsaw/internal/initcmd"
	"github.com/chainsaw-dev/chainsaw/internal/report"
	"github.com/chainsaw-dev/chainsaw/internal/sbom"
	"github.com/chainsaw-dev/chainsaw/internal/scanner"
	"github.com/chainsaw-dev/chainsaw/internal/trend"
	"github.com/chainsaw-dev/chainsaw/internal/vuln"
	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
	root.AddCommand(checkCmd())
	root.AddCommand(evidenceCmd())
	root.AddCommand(initSecurityCmd())
	root.AddCommand(initCICmd())
	root.AddCommand(diffCmd())

	return root
}

func diffCmd() *cobra.Command {
	var (
		basePath   string
		headPath   string
		format     string
		failOn     string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two scan results to show changes",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Determine output writer.
			var w *os.File
			if outputPath != "" {
				f, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			} else {
				w = os.Stdout
			}

			base, err := diff.LoadScanResult(basePath)
			if err != nil {
				return fmt.Errorf("loading base scan: %w", err)
			}

			head, err := diff.LoadScanResult(headPath)
			if err != nil {
				return fmt.Errorf("loading head scan: %w", err)
			}

			result := diff.Compare(base, head)

			switch format {
			case "json":
				if err := diff.WriteDiffJSON(ctx, w, result); err != nil {
					return err
				}
			case "markdown":
				if err := diff.WriteDiffMarkdown(ctx, w, result); err != nil {
					return err
				}
			default:
				if err := diff.WriteDiffReport(ctx, w, result); err != nil {
					return err
				}
			}

			if failOn != "" {
				threshold := models.ParseSeverity(failOn)
				for _, f := range result.NewVulnerabilities {
					if models.SeverityRank(f.Severity) >= models.SeverityRank(threshold) {
						os.Exit(1)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&basePath, "base", "", "Path to base scan JSON file (required)")
	cmd.Flags().StringVar(&headPath, "head", "", "Path to head scan JSON file (required)")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json, markdown")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Severity threshold for new vulnerabilities to trigger exit code 1")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file instead of stdout")
	_ = cmd.MarkFlagRequired("base")
	_ = cmd.MarkFlagRequired("head")

	return cmd
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
		format         string
		failOn         string
		ecosystem      string
		policyPath     string
		detectLicences bool
		outputPath     string
		quiet          bool
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

			// Determine output writer.
			var w *os.File
			if outputPath != "" {
				f, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			} else {
				w = os.Stdout
			}

			// Load policy.
			pol, err := engine.LoadPolicy(ctx, policyPath)
			if err != nil {
				return err
			}

			// Override fail-on from flag if set explicitly.
			if cmd.Flags().Changed("fail-on") {
				pol.FailOn = models.ParseSeverity(failOn)
			}

			// Resolve scanners, optionally filtered by ecosystem.
			scanners := engine.ResolveScanners(ecosystem)
			if len(scanners) == 0 {
				return fmt.Errorf("no scanners registered for ecosystems: %s", ecosystem)
			}

		// Detect and parse dependencies.
		var components []models.Component
		var warnings []string
		for _, s := range scanners {
			if !quiet {
				fmt.Fprintf(os.Stderr, "Scanning %s...\n", s.Ecosystem())
			}
			manifests, err := s.DetectManifests(ctx, root)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("scanner %s: %v", s.Ecosystem(), err))
				continue
			}
			for _, m := range manifests {
				deps, err := s.ParseDependencies(ctx, m)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("parsing %s: %v", m, err))
					continue
				}
				components = append(components, deps...)
			}
		}

			// Vulnerability matching.
			if !quiet && len(components) > 0 {
				fmt.Fprintf(os.Stderr, "Querying vulnerabilities for %d components...\n", len(components))
			}
			client := vuln.NewClient()
			matcher := vuln.NewMatcher(client)
			findings, err := matcher.Match(ctx, components)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("vulnerability matching: %v", err))
			}

		// Hygiene checks.
		var hygieneFindings []models.Finding
		hygieneFindings = append(hygieneFindings, hygiene.CheckTyposquatting(components)...)
		hygieneFindings = append(hygieneFindings, hygiene.CheckIntegrity(components)...)
		hygieneFindings = append(hygieneFindings, hygiene.CheckActionSecurity(components)...)
		hygieneFindings = append(hygieneFindings, hygiene.CheckDockerfiles(root)...)

		// Licence detection (optional).
			if detectLicences {
				det := licence.NewDetector()
				if _, err := det.DetectAll(ctx, components); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
				}
				licFindings := licence.EvaluateLicences(
					components,
					pol.Licences.Mode,
					pol.Licences.AllowList,
					pol.Licences.DenyList,
				)
				hygieneFindings = append(hygieneFindings, licFindings...)
			}

			result := models.ScanResult{
				Components:  components,
				Findings:    findings,
				Hygiene:     hygieneFindings,
				Warnings:    warnings,
				Timestamp:   time.Now(),
				ToolVersion: version,
			}

			// Evaluate policy.
			_, exitCode := pol.Evaluate(result)

			// Output.
			if err := writeOutput(ctx, w, format, result); err != nil {
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
	cmd.Flags().BoolVar(&detectLicences, "detect-licences", false, "Detect licences for dependencies via registry APIs")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress messages to stderr")

	return cmd
}

func sbomCmd() *cobra.Command {
	var (
		format     string
		outputPath string
	)

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

			// Determine output writer.
			var w *os.File
			if outputPath != "" {
				f, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			} else {
				w = os.Stdout
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
				_, err = w.Write(data)
				if err != nil {
					return fmt.Errorf("writing SBOM: %w", err)
				}
				fmt.Fprintln(w)
			default:
				return fmt.Errorf("unsupported SBOM format: %s", format)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "cyclonedx", "SBOM format: cyclonedx")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file instead of stdout")

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
		showTrend  bool
		outputPath string
		quiet      bool
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

			// Determine output writer.
			var w *os.File
			if outputPath != "" {
				f, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			} else {
				w = os.Stdout
			}

		// Load policy to check for CRA config.
		pol, err := engine.LoadPolicy(ctx, policyPath)
		if err != nil {
			return err
		}

		craConfig := &cra.CRAConfig{
			ProductName:     pol.CRA.Manufacturer,
			Manufacturer:    pol.CRA.Manufacturer,
			SecurityContact: pol.CRA.SecurityContact,
			SupportEndDate:  pol.CRA.SupportEndDate,
			CSIRTContact:    pol.CRA.CSIRTContact,
		}

		// Detect and parse all dependencies.
		scanners := engine.ResolveScanners("")
		var components []models.Component
		var warnings []string
		for _, s := range scanners {
			if !quiet {
				fmt.Fprintf(os.Stderr, "Scanning %s...\n", s.Ecosystem())
			}
			manifests, err := s.DetectManifests(ctx, root)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("scanner %s: %v", s.Ecosystem(), err))
				continue
			}
			for _, m := range manifests {
				deps, err := s.ParseDependencies(ctx, m)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("parsing %s: %v", m, err))
					continue
				}
				components = append(components, deps...)
			}
		}

			// Vulnerability matching.
			if !quiet && len(components) > 0 {
				fmt.Fprintf(os.Stderr, "Querying vulnerabilities for %d components...\n", len(components))
			}
			client := vuln.NewClient()
			matcher := vuln.NewMatcher(client)
			findings, err := matcher.Match(ctx, components)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("vulnerability matching: %v", err))
			}

		// Hygiene checks.
		var hygieneFindings []models.Finding
		hygieneFindings = append(hygieneFindings, hygiene.CheckTyposquatting(components)...)
		hygieneFindings = append(hygieneFindings, hygiene.CheckIntegrity(components)...)
		hygieneFindings = append(hygieneFindings, hygiene.CheckActionSecurity(components)...)
		hygieneFindings = append(hygieneFindings, hygiene.CheckDockerfiles(root)...)

		// Build assessment context and run CRA checks.
			if !quiet {
				fmt.Fprintf(os.Stderr, "Assessing CRA compliance...\n")
			}
			assessCtx := cra.AssessmentContext{
				RootPath:    root,
				Components:  components,
				Findings:    findings,
				Hygiene:     hygieneFindings,
				ToolVersion: version,
				Config:      craConfig,
			}
			result := cra.Assess(ctx, &assessCtx)

			// Save result to trend history.
			if err := trend.SaveResult(root, result); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not save trend data: %v\n", err)
			}

			// Show trend if requested.
			if showTrend {
				history, err := trend.LoadHistory(root)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: could not load trend data: %v\n", err)
				} else {
					current := trend.TrendEntry{
						Date:         result.Date,
						OverallScore: result.OverallScore,
					}
					// Count check statuses.
					for _, c := range result.Checks {
						switch c.Status {
						case models.CRAPass:
							current.PassCount++
						case models.CRAFail:
							current.FailCount++
						case models.CRAWarn:
							current.WarnCount++
						}
					}
					current.TotalChecks = len(result.Checks)
					fmt.Fprintln(os.Stderr, trend.FormatTrend(history, current))
				}
			}

			// Evaluate CRA result against policy.
			pass, reason := pol.EvaluateCRA(result)
			if !pass {
				fmt.Fprintf(os.Stderr, "Policy violation: %s\n", reason)
			}

			// Output.
			switch format {
			case "json":
				return cra.WriteComplianceJSON(ctx, w, result)
			default:
				return cra.WriteComplianceReport(ctx, w, result)
			}
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to .chainsaw.yaml policy file")
	cmd.Flags().BoolVar(&showTrend, "trend", false, "Show CRA score trend since last assessment")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress messages to stderr")

	return cmd
}

func supplyChainCmd() *cobra.Command {
	var (
		format     string
		policyPath string
		outputPath string
		quiet      bool
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

			// Determine output writer.
			var w *os.File
			if outputPath != "" {
				f, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			} else {
				w = os.Stdout
			}

		// Load policy.
		pol, err := engine.LoadPolicy(ctx, policyPath)
		if err != nil {
			return err
		}

		// Detect and parse all dependencies.
		scanners := engine.ResolveScanners("")
		var components []models.Component
		var warnings []string
		for _, s := range scanners {
			if !quiet {
				fmt.Fprintf(os.Stderr, "Scanning %s...\n", s.Ecosystem())
			}
			manifests, err := s.DetectManifests(ctx, root)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("scanner %s: %v", s.Ecosystem(), err))
				continue
			}
			for _, m := range manifests {
				deps, err := s.ParseDependencies(ctx, m)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("parsing %s: %v", m, err))
					continue
				}
				components = append(components, deps...)
			}
		}

		// Enrich each component with supply chain metadata.
		if !quiet {
			fmt.Fprintf(os.Stderr, "Analysing supply chain...\n")
		}
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
				return analysis.WriteSupplyChainJSON(ctx, w, result)
			default:
				return analysis.WriteSupplyChainReport(ctx, w, result)
			}
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to .chainsaw.yaml policy file")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress messages to stderr")

	return cmd
}

func checkCmd() *cobra.Command {
	var (
		format     string
		failOn     string
		ecosystem  string
		policyPath string
		outputPath string
		quiet      bool
	)

	cmd := &cobra.Command{
		Use:   "check [path]",
		Short: "Run scan, comply, and supply-chain checks in one invocation",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			// Determine output writer.
			var w *os.File
			if outputPath != "" {
				f, err := os.Create(outputPath)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			} else {
				w = os.Stdout
			}

			// Load policy.
			pol, err := engine.LoadPolicy(ctx, policyPath)
			if err != nil {
				return err
			}

			// Override fail-on from flag if set explicitly.
			if cmd.Flags().Changed("fail-on") {
				pol.FailOn = models.ParseSeverity(failOn)
			}

			// Resolve scanners, optionally filtered by ecosystem.
			scanners := engine.ResolveScanners(ecosystem)
			if len(scanners) == 0 {
				return fmt.Errorf("no scanners registered for ecosystems: %s", ecosystem)
			}

			// Detect and parse dependencies.
			var components []models.Component
			var warnings []string
			for _, s := range scanners {
				if !quiet {
					fmt.Fprintf(os.Stderr, "Scanning %s...\n", s.Ecosystem())
				}
				manifests, err := s.DetectManifests(ctx, root)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("scanner %s: %v", s.Ecosystem(), err))
					continue
				}
				for _, m := range manifests {
					deps, err := s.ParseDependencies(ctx, m)
					if err != nil {
						warnings = append(warnings, fmt.Sprintf("parsing %s: %v", m, err))
						continue
					}
					components = append(components, deps...)
				}
			}

			// Vulnerability matching.
			if !quiet && len(components) > 0 {
				fmt.Fprintf(os.Stderr, "Querying vulnerabilities for %d components...\n", len(components))
			}
			client := vuln.NewClient()
			matcher := vuln.NewMatcher(client)
			findings, err := matcher.Match(ctx, components)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("vulnerability matching: %v", err))
			}

		// Hygiene checks.
		var hygieneFindings []models.Finding
		hygieneFindings = append(hygieneFindings, hygiene.CheckTyposquatting(components)...)
		hygieneFindings = append(hygieneFindings, hygiene.CheckIntegrity(components)...)
		hygieneFindings = append(hygieneFindings, hygiene.CheckActionSecurity(components)...)
		hygieneFindings = append(hygieneFindings, hygiene.CheckDockerfiles(root)...)

		// Build scan result.
			scanResult := models.ScanResult{
				Components:  components,
				Findings:    findings,
				Hygiene:     hygieneFindings,
				Warnings:    warnings,
				Timestamp:   time.Now(),
				ToolVersion: version,
			}

			// CRA assessment.
			if !quiet {
				fmt.Fprintf(os.Stderr, "Assessing CRA compliance...\n")
			}
			craConfig := &cra.CRAConfig{
				ProductName:     pol.CRA.Manufacturer,
				Manufacturer:    pol.CRA.Manufacturer,
				SecurityContact: pol.CRA.SecurityContact,
				SupportEndDate:  pol.CRA.SupportEndDate,
				CSIRTContact:    pol.CRA.CSIRTContact,
			}
			assessCtx := cra.AssessmentContext{
				RootPath:    root,
				Components:  components,
				Findings:    findings,
				Hygiene:     hygieneFindings,
				ToolVersion: version,
				Config:      craConfig,
			}
			craResult := cra.Assess(ctx, &assessCtx)

			// Supply chain analysis.
			if !quiet {
				fmt.Fprintf(os.Stderr, "Analysing supply chain...\n")
			}
			var enriched []models.InfraComponent
			for _, c := range components {
				enriched = append(enriched, analysis.EnrichComponent(c))
			}
			pinningScore := analysis.CalculatePinningScore(enriched)
			blastRadii := analysis.AssessAll(enriched)
			scResult := models.SupplyChainResult{
				Components:   enriched,
				PinningScore: pinningScore,
				BlastRadii:   blastRadii,
				Timestamp:    time.Now(),
				ToolVersion:  version,
			}

			// Evaluate policies.
			_, scanExitCode := pol.Evaluate(scanResult)
			craPass, _ := pol.EvaluateCRA(craResult)
			scPass, _ := pol.EvaluateSupplyChain(scResult)

			// Output.
			var writeErr error
			switch format {
			case "json":
				writeErr = writeCheckJSON(ctx, w, scanResult, craResult, scResult)
			default:
				writeErr = writeCheckTable(ctx, w, scanResult, craResult, scResult)
			}
			if writeErr != nil {
				return writeErr
			}

			// Exit code: 0 if all pass, 1 if any fail.
			if scanExitCode != 0 || !craPass || !scPass {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Minimum severity to fail on (CRITICAL, HIGH, MEDIUM, LOW)")
	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", "Comma-separated ecosystems to scan (e.g. go,npm)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to .chainsaw.yaml policy file")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress messages to stderr")

	return cmd
}

func evidenceCmd() *cobra.Command {
	var (
		policyPath  string
		ecosystem   string
		outputPath  string
		quiet       bool
		productName string
	)

	cmd := &cobra.Command{
		Use:   "evidence [path]",
		Short: "Generate CRA evidence export bundle",
		Long:  "Run scan, comply, and supply-chain checks, then bundle all results into a ZIP archive with manifest.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			// Default output path if not specified
			if outputPath == "" {
				outputPath = time.Now().Format("evidence-2006-01-02-150405.zip")
			}

			// Determine product name
			prod := productName
			if prod == "" {
				prod = "Product"
			}

			// Load policy
			pol, err := engine.LoadPolicy(ctx, policyPath)
			if err != nil {
				return err
			}

			// Resolve scanners
			scanners := engine.ResolveScanners(ecosystem)
			if len(scanners) == 0 {
				return fmt.Errorf("no scanners registered for ecosystems: %s", ecosystem)
			}

			// Run full scan pipeline (reuse from checkCmd)
			var components []models.Component
			var warnings []string
			for _, s := range scanners {
				if !quiet {
					fmt.Fprintf(os.Stderr, "Scanning %s...\n", s.Ecosystem())
				}
				manifests, err := s.DetectManifests(ctx, root)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("scanner %s: %v", s.Ecosystem(), err))
					continue
				}
				for _, m := range manifests {
					deps, err := s.ParseDependencies(ctx, m)
					if err != nil {
						warnings = append(warnings, fmt.Sprintf("parsing %s: %v", m, err))
						continue
					}
					components = append(components, deps...)
				}
			}

			// Vulnerability matching
			if !quiet && len(components) > 0 {
				fmt.Fprintf(os.Stderr, "Querying vulnerabilities for %d components...\n", len(components))
			}
			client := vuln.NewClient()
			matcher := vuln.NewMatcher(client)
			findings, err := matcher.Match(ctx, components)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("vulnerability matching: %v", err))
			}

			// Hygiene checks
			var hygieneFindings []models.Finding
			hygieneFindings = append(hygieneFindings, hygiene.CheckTyposquatting(components)...)
			hygieneFindings = append(hygieneFindings, hygiene.CheckIntegrity(components)...)
			hygieneFindings = append(hygieneFindings, hygiene.CheckActionSecurity(components)...)
			hygieneFindings = append(hygieneFindings, hygiene.CheckDockerfiles(root)...)

			// Build scan result
			scanResult := models.ScanResult{
				Components:  components,
				Findings:    findings,
				Hygiene:     hygieneFindings,
				Warnings:    warnings,
				Timestamp:   time.Now(),
				ToolVersion: version,
			}

			// CRA assessment
			if !quiet {
				fmt.Fprintf(os.Stderr, "Assessing CRA compliance...\n")
			}
			craConfig := &cra.CRAConfig{
				ProductName:     pol.CRA.Manufacturer,
				Manufacturer:    pol.CRA.Manufacturer,
				SecurityContact: pol.CRA.SecurityContact,
				SupportEndDate:  pol.CRA.SupportEndDate,
				CSIRTContact:    pol.CRA.CSIRTContact,
			}
			assessCtx := cra.AssessmentContext{
				RootPath:    root,
				Components:  components,
				Findings:    findings,
				Hygiene:     hygieneFindings,
				ToolVersion: version,
				Config:      craConfig,
			}
			craResult := cra.Assess(ctx, &assessCtx)

			// Supply chain analysis
			if !quiet {
				fmt.Fprintf(os.Stderr, "Analysing supply chain...\n")
			}
			var enriched []models.InfraComponent
			for _, c := range components {
				enriched = append(enriched, analysis.EnrichComponent(c))
			}
			pinningScore := analysis.CalculatePinningScore(enriched)
			blastRadii := analysis.AssessAll(enriched)
			scResult := models.SupplyChainResult{
				Components:   enriched,
				PinningScore: pinningScore,
				BlastRadii:   blastRadii,
				Timestamp:    time.Now(),
				ToolVersion:  version,
			}

			// Generate SBOM
			if !quiet {
				fmt.Fprintf(os.Stderr, "Generating SBOM...\n")
			}
			sbomData, err := sbom.GenerateCycloneDX(components, version)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: SBOM generation failed: %v\n", err)
				sbomData = nil
			}

			// Generate evidence bundle
			if !quiet {
				fmt.Fprintf(os.Stderr, "Writing evidence bundle...\n")
			}
			out, err := os.Create(outputPath)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer out.Close()

			cfg := evidence.BundleConfig{
				ProductName: prod,
				ToolVersion: version,
				ScanResult:  scanResult,
				CRAResult:   craResult,
				SupplyChain: scResult,
				SBOMData:    sbomData,
			}
			if err := evidence.GenerateBundle(ctx, out, cfg); err != nil {
				return fmt.Errorf("generating evidence bundle: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Evidence bundle written to: %s\n", outputPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to .chainsaw.yaml policy file")
	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", "Comma-separated ecosystems to scan (e.g. go,npm)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write evidence bundle to file (default: evidence-YYYY-MM-DD-HHMMSS.zip)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress messages to stderr")
	cmd.Flags().StringVar(&productName, "product", "", "Product name for the evidence bundle (default: Product)")

	return cmd
}

func writeCheckTable(ctx context.Context, w *os.File, scanResult models.ScanResult, craResult models.CRAResult, scResult models.SupplyChainResult) error {
	fmt.Fprintln(w, "=== Vulnerability Scan ===")
	if err := report.WriteTable(ctx, w, scanResult); err != nil {
		return err
	}

	fmt.Fprintln(w, "\n=== CRA Compliance ===")
	if err := cra.WriteComplianceReport(ctx, w, craResult); err != nil {
		return err
	}

	fmt.Fprintln(w, "\n=== Supply Chain ===")
	if err := analysis.WriteSupplyChainReport(ctx, w, scResult); err != nil {
		return err
	}

	// Summary.
	vulnCount := len(scanResult.Findings)
	fmt.Fprintf(w, "\n=== Summary ===\n")
	fmt.Fprintf(w, "Components: %d | Vulnerabilities: %d | CRA Score: %d%% | Pinning Score: %d%%\n",
		len(scanResult.Components), vulnCount, craResult.OverallScore, scResult.PinningScore)

	return nil
}

func writeCheckJSON(ctx context.Context, w *os.File, scanResult models.ScanResult, craResult models.CRAResult, scResult models.SupplyChainResult) error {
	type CheckOutput struct {
		Scan         models.ScanResult         `json:"scan"`
		Compliance   models.CRAResult          `json:"compliance"`
		SupplyChain  models.SupplyChainResult  `json:"supply_chain"`
		Summary      map[string]interface{}   `json:"summary"`
	}

	output := CheckOutput{
		Scan:        scanResult,
		Compliance:  craResult,
		SupplyChain: scResult,
		Summary: map[string]interface{}{
			"components":     len(scanResult.Components),
			"vulnerabilities": len(scanResult.Findings),
			"cra_score":      craResult.OverallScore,
			"pinning_score":  scResult.PinningScore,
		},
	}

	// Marshal to JSON and write.
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
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
