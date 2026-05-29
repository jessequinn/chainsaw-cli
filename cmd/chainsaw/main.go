package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/chainsaw-dev/chainsaw/internal/analysis"
	"github.com/chainsaw-dev/chainsaw/internal/baseline"
	"github.com/chainsaw-dev/chainsaw/internal/cra"
	"github.com/chainsaw-dev/chainsaw/internal/diff"
	"github.com/chainsaw-dev/chainsaw/internal/engine"
	"github.com/chainsaw-dev/chainsaw/internal/evidence"
	"github.com/chainsaw-dev/chainsaw/internal/hygiene"
	"github.com/chainsaw-dev/chainsaw/internal/initcmd"
	"github.com/chainsaw-dev/chainsaw/internal/licence"
	"github.com/chainsaw-dev/chainsaw/internal/report"
	"github.com/chainsaw-dev/chainsaw/internal/sbom"
	"github.com/chainsaw-dev/chainsaw/internal/scanner"
	"github.com/chainsaw-dev/chainsaw/internal/schema"
	"github.com/chainsaw-dev/chainsaw/internal/trend"
	"github.com/chainsaw-dev/chainsaw/internal/vuln"
	"github.com/chainsaw-dev/chainsaw/internal/watch"
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
		Use:           "chainsaw",
		Short:         "Supply chain security scanner for CRA compliance",
		Long:          "Chainsaw scans dependency trees and lockfiles to surface vulnerabilities, licence violations, typosquatting, and lockfile integrity issues.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(scanCmd())
	root.AddCommand(sbomCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(completionCmd())
	root.AddCommand(complyCmd())
	root.AddCommand(supplyChainCmd())
	root.AddCommand(checkCmd())
	root.AddCommand(evidenceCmd())
	root.AddCommand(initSecurityCmd())
	root.AddCommand(initCICmd())
	root.AddCommand(initCRACmd())
	root.AddCommand(initHooksCmd())
	root.AddCommand(diffCmd())
	root.AddCommand(baselineCmd())
	root.AddCommand(generateDeclarationCmd())
	root.AddCommand(generateDocsCmd())
	root.AddCommand(schemaCmd())
	root.AddCommand(watchCmd())

	return root
}

func baselineCmd() *cobra.Command {
	var (
		ecosystem string
		update    bool
		quiet     bool
	)

	cmd := &cobra.Command{
		Use:   "baseline [path]",
		Short: "Save or update the findings baseline",
		Long:  "Scan the project and save all current finding IDs as the baseline. Future scans will only report new findings not in the baseline.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			root := "."
			if len(args) > 0 {
				root = args[0]
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

			scanResult := models.ScanResult{
				Components:  components,
				Findings:    findings,
				Hygiene:     hygieneFindings,
				Warnings:    warnings,
				Timestamp:   time.Now(),
				ToolVersion: version,
			}

			var saveErr error
			if update {
				saveErr = baseline.Update(root, scanResult)
			} else {
				saveErr = baseline.Save(root, scanResult)
			}
			if saveErr != nil {
				return fmt.Errorf("saving baseline: %w", saveErr)
			}

			total := len(findings) + len(hygieneFindings)
			if !quiet {
				if update {
					fmt.Fprintf(os.Stderr, "Baseline updated: %d findings recorded to %s\n", total, baseline.DefaultFile)
				} else {
					fmt.Fprintf(os.Stderr, "Baseline saved: %d findings recorded to %s\n", total, baseline.DefaultFile)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", "Limit to ecosystem (go, npm, python, etc.)")
	cmd.Flags().BoolVar(&update, "update", false, "Update existing baseline (preserves created date)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress messages")

	return cmd
}

func generateDeclarationCmd() *cobra.Command {
	var (
		ecosystem  string
		policyPath string
		outputPath string
		quiet      bool
		product    string
		version_   string
		category   string
		address    string
	)

	cmd := &cobra.Command{
		Use:   "generate-declaration [path]",
		Short: "Generate EU Declaration of Conformity (CRA Article 28)",
		Long:  "Generate a Markdown EU Declaration of Conformity per CRA Article 28, incorporating scan and compliance results.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			// Default output path if not specified
			if outputPath == "" {
				outputPath = "DECLARATION-OF-CONFORMITY.md"
			}

			// Determine product name
			prod := product
			if prod == "" {
				prod = "Product"
			}

			// Determine version
			ver := version_
			if ver == "" {
				ver = "1.0.0"
			}

			// Load policy to get CRA config
			pol, err := engine.LoadPolicy(ctx, policyPath)
			if err != nil {
				return err
			}

			craConfig := &cra.CRAConfig{
				ProductName:     product,
				Manufacturer:    pol.CRA.Manufacturer,
				SecurityContact: pol.CRA.SecurityContact,
				SupportEndDate:  pol.CRA.SupportEndDate,
				CSIRTContact:    pol.CRA.CSIRTContact,
				ProductCategory: category,
			}

			// Detect and parse all dependencies
			scanners := engine.ResolveScanners(ecosystem)
			if len(scanners) == 0 {
				return fmt.Errorf("no scanners registered for ecosystems: %s", ecosystem)
			}

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
			vulnClient := vuln.NewClient()
			matcher := vuln.NewMatcher(vulnClient)
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

			// Build assessment context and run CRA checks
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

			// Create output file
			f, err := os.Create(outputPath)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer f.Close()

			// Generate declaration
			decCfg := cra.DeclarationConfig{
				ProductName:    prod,
				Manufacturer:   pol.CRA.Manufacturer,
				ProductVersion: ver,
				Category:       category,
				Address:        address,
				CRAResult:      result,
			}

			if err := cra.WriteDeclaration(f, decCfg); err != nil {
				return fmt.Errorf("writing declaration: %w", err)
			}

			if !quiet {
				fmt.Fprintf(os.Stderr, "EU Declaration of Conformity generated: %s\n", outputPath)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", "Filter scanners by ecosystem (e.g., go, npm, python)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to .chainsaw.yaml policy file")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "DECLARATION-OF-CONFORMITY.md", "Output file path")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress messages to stderr")
	cmd.Flags().StringVar(&product, "product", "", "Product name (required)")
	cmd.Flags().StringVar(&version_, "version", "1.0.0", "Product version")
	cmd.Flags().StringVar(&category, "category", "default", "Product category: critical, important-class-2, important-class-1, or default")
	cmd.Flags().StringVar(&address, "address", "", "Manufacturer's registered address")
	_ = cmd.MarkFlagRequired("product")

	return cmd
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
		platform   string
	)

	cmd := &cobra.Command{
		Use:   "init-ci [path]",
		Short: "Generate CI workflow for supply chain scanning",
		Long:  "Generate CI workflow file (GitHub Actions, GitLab CI, etc.) for supply chain scanning.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			switch platform {
			case "github":
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

				fmt.Fprintln(os.Stdout, "Created GitHub Actions workflow:")
				for _, f := range written {
					fmt.Fprintf(os.Stdout, "  %s\n", f)
				}
				return nil

			case "gitlab":
				path, err := initcmd.WriteGitLabCI(root)
				if err != nil {
					return fmt.Errorf("writing GitLab CI file: %w", err)
				}

				fmt.Fprintln(os.Stdout, "Created GitLab CI configuration:")
				fmt.Fprintf(os.Stdout, "  %s\n", path)
				return nil

			default:
				return fmt.Errorf("unsupported platform %q; supported platforms: github, gitlab", platform)
			}
		},
	}

	cmd.Flags().StringVar(&platform, "platform", "github", "CI platform: github, gitlab")
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
		showTree       bool
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

			// Dependency tree (if enabled and format is table).
			if showTree && format == "table" {
				fmt.Fprintln(w)
				if err := report.WriteTree(w, result.Components); err != nil {
					return err
				}
			}

			if exitCode != 0 {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json, sarif, markdown")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Minimum severity to fail on (CRITICAL, HIGH, MEDIUM, LOW)")
	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", "Comma-separated ecosystems to scan (e.g. go,npm)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to .chainsaw.yaml policy file")
	cmd.Flags().BoolVar(&detectLicences, "detect-licences", false, "Detect licences for dependencies via registry APIs")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress messages to stderr")
	cmd.Flags().BoolVar(&showTree, "tree", false, "Show dependency tree visualization (with --format=table)")

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

func completionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate shell completion script for bash, zsh, fish, or powershell.

To use bash completion:
  chainsaw completion bash | sudo tee /usr/share/bash-completion.d/chainsaw

To use zsh completion:
  chainsaw completion zsh | sudo tee /usr/share/zsh/site-functions/_chainsaw

To use fish completion:
  chainsaw completion fish | sudo tee /usr/share/fish/vendor_completions.d/chainsaw.fish

To use powershell completion:
  chainsaw completion powershell | Out-String | Out-File -FilePath $PROFILE -Append`,
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return nil
		},
		DisableFlagsInUseLine: true,
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
			case "sarif":
				return cra.WriteCRASARIF(ctx, w, result)
			case "markdown":
				return report.WriteCRAMarkdown(ctx, w, result)
			default:
				return cra.WriteComplianceReport(ctx, w, result)
			}
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json, sarif, markdown")
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
		Scan        models.ScanResult        `json:"scan"`
		Compliance  models.CRAResult         `json:"compliance"`
		SupplyChain models.SupplyChainResult `json:"supply_chain"`
		Summary     map[string]interface{}   `json:"summary"`
	}

	output := CheckOutput{
		Scan:        scanResult,
		Compliance:  craResult,
		SupplyChain: scResult,
		Summary: map[string]interface{}{
			"components":      len(scanResult.Components),
			"vulnerabilities": len(scanResult.Findings),
			"cra_score":       craResult.OverallScore,
			"pinning_score":   scResult.PinningScore,
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

func initCRACmd() *cobra.Command {
	var (
		product      string
		manufacturer string
		category     string
		email        string
		supportEnd   string
		csirt        string
		force        bool
	)

	cmd := &cobra.Command{
		Use:   "init-cra [path]",
		Short: "Initialize CRA compliance configuration",
		Long:  "Generate a .chainsaw.yaml preconfigured for EU Cyber Resilience Act compliance.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			if category != "" && !initcmd.ValidateCategory(category) {
				return fmt.Errorf("invalid category %q; valid values: %v", category, initcmd.ValidCategories())
			}

			cfg := initcmd.DefaultCRAConfig()
			if product != "" {
				cfg.ProductName = product
			}
			if manufacturer != "" {
				cfg.Manufacturer = manufacturer
			}
			if category != "" {
				cfg.Category = category
			}
			if email != "" {
				cfg.SecurityContact = email
			}
			if supportEnd != "" {
				cfg.SupportEndDate = supportEnd
			}
			if csirt != "" {
				cfg.CSIRTContact = csirt
			}

			var (
				path string
				err  error
			)
			if force {
				path, err = initcmd.WriteCRAConfigForce(root, cfg)
			} else {
				path, err = initcmd.WriteCRAConfig(root, cfg)
			}
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stdout, "Created CRA configuration: %s\n", path)
			fmt.Fprint(os.Stdout, initcmd.FormatNextSteps(cfg.Category))
			return nil
		},
	}

	cmd.Flags().StringVar(&product, "product", "", "Product name")
	cmd.Flags().StringVar(&manufacturer, "manufacturer", "", "Manufacturer/organization name")
	cmd.Flags().StringVar(&category, "category", "", "CRA product category (default, important-class-1, important-class-2, critical)")
	cmd.Flags().StringVar(&email, "email", "", "Security contact email")
	cmd.Flags().StringVar(&supportEnd, "support-end-date", "", "Support end date (YYYY-MM-DD)")
	cmd.Flags().StringVar(&csirt, "csirt-contact", "", "CSIRT notification contact")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing .chainsaw.yaml")

	return cmd
}

func generateDocsCmd() *cobra.Command {
	var (
		ecosystem  string
		policyPath string
		outputPath string
		quiet      bool
		product    string
		version_   string
		category   string
	)

	cmd := &cobra.Command{
		Use:   "generate-docs [path]",
		Short: "Generate CRA Article 10 technical documentation",
		Long:  "Generate a Markdown skeleton for CRA Article 10(2) technical documentation, incorporating scan and compliance results.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			// Default output path if not specified
			if outputPath == "" {
				outputPath = "TECHNICAL-DOCUMENTATION.md"
			}

			// Determine product name
			prod := product
			if prod == "" {
				prod = "Product"
			}

			// Load policy
			pol, err := engine.LoadPolicy(ctx, policyPath)
			if err != nil {
				return err
			}

			// Resolve scanners, optionally filtered by ecosystem
			scanners := engine.ResolveScanners(ecosystem)
			if len(scanners) == 0 {
				return fmt.Errorf("no scanners registered for ecosystems: %s", ecosystem)
			}

			// Run scan pipeline to gather component data
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

			// Build CRA assessment
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

			// Determine product version
			vers := version_
			if vers == "" {
				vers = version
			}

			// Determine category
			cat := category
			if cat == "" {
				cat = "default"
			}

			// Generate technical documentation
			if !quiet {
				fmt.Fprintf(os.Stderr, "Generating technical documentation...\n")
			}

			docCfg := cra.TechDocConfig{
				ProductName:    prod,
				Manufacturer:   pol.CRA.Manufacturer,
				ProductVersion: vers,
				Category:       cat,
				SupportEndDate: pol.CRA.SupportEndDate,
				Components:     components,
				CRAResult:      craResult,
			}

			out, err := os.Create(outputPath)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer out.Close()

			if err := cra.WriteTechDoc(out, docCfg); err != nil {
				return fmt.Errorf("writing technical documentation: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Technical documentation written to: %s\n", outputPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", "Comma-separated ecosystems to scan (e.g. go,npm)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to .chainsaw.yaml policy file")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write output to file (default: TECHNICAL-DOCUMENTATION.md)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress messages to stderr")
	cmd.Flags().StringVar(&product, "product", "", "Product name (default: Product)")
	cmd.Flags().StringVar(&version_, "version", "", "Product version (default: tool version)")
	cmd.Flags().StringVar(&category, "category", "", "CRA category: default, important-class-1, important-class-2, critical (default: default)")

	return cmd
}

func initHooksCmd() *cobra.Command {
	var (
		framework string
		force     bool
	)

	cmd := &cobra.Command{
		Use:   "init-hooks [path]",
		Short: "Set up git pre-commit hooks for security scanning",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			var (
				path string
				err  error
			)

			switch framework {
			case "native":
				if force {
					path, err = initcmd.WriteNativeHookForce(root)
				} else {
					path, err = initcmd.WriteNativeHook(root)
				}
			case "pre-commit":
				path, err = initcmd.WritePreCommitConfig(root)
			default:
				return fmt.Errorf("unknown framework %q; use 'native' or 'pre-commit'", framework)
			}

			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stdout, "Created: %s\n", path)
			if framework == "pre-commit" {
				fmt.Fprintln(os.Stdout, "Run 'pre-commit install' to activate the hook.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&framework, "framework", "native", "Hook framework: native, pre-commit")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing hook")

	return cmd
}

func schemaCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Print JSON schemas for chainsaw output formats",
		Long:  "Print or list available JSON schemas for chainsaw output formats and policy files.",
		RunE: func(cmd *cobra.Command, args []string) error {
			schemas := schema.AllSchemas()
			if name != "" {
				s, ok := schemas[name]
				if !ok {
					return fmt.Errorf("unknown schema %q; available: scan-result, cra-result, supply-chain-result, policy", name)
				}
				return schema.WriteSchema(os.Stdout, s)
			}
			// Print all schema names.
			for k := range schemas {
				fmt.Println(k)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Schema name (scan-result, cra-result, supply-chain-result, policy)")
	return cmd
}

func watchCmd() *cobra.Command {
	var (
		ecosystem string
		quiet     bool
	)

	cmd := &cobra.Command{
		Use:   "watch [path]",
		Short: "Watch lockfiles and re-scan on changes",
		Long:  "Poll lockfiles for changes and automatically re-scan. Press Ctrl+C to exit.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			root := "."
			if len(args) > 0 {
				root = args[0]
			}

			if !quiet {
				fmt.Fprintf(os.Stderr, "Watching for lockfile changes in %s...\n", root)
				fmt.Fprintln(os.Stderr, "Press Ctrl+C to stop.")
			}

			prevCount := 0
			cfg := watch.DefaultWatchConfig(root)
			cfg.OnChange = func(ctx context.Context, events []watch.ChangeEvent) error {
				if !quiet {
					for _, e := range events {
						fmt.Fprintf(os.Stderr, "Changed: %s\n", e.File)
					}
					fmt.Fprintln(os.Stderr, "Re-scanning...")
				}

				scanners := engine.ResolveScanners(ecosystem)
				var components []models.Component
				for _, s := range scanners {
					manifests, err := s.DetectManifests(ctx, root)
					if err != nil {
						continue
					}
					for _, m := range manifests {
						deps, err := s.ParseDependencies(ctx, m)
						if err != nil {
							continue
						}
						components = append(components, deps...)
					}
				}

				client := vuln.NewClient()
				matcher := vuln.NewMatcher(client)
				findings, _ := matcher.Match(ctx, components)

				hygieneFindings := hygiene.CheckTyposquatting(components)
				hygieneFindings = append(hygieneFindings, hygiene.CheckIntegrity(components)...)

				total := len(findings) + len(hygieneFindings)

				if !quiet {
					fmt.Fprintf(os.Stderr, "%s\n", watch.FormatDelta(prevCount, total))
				}
				prevCount = total
				return nil
			}

			return watch.Watch(ctx, cfg)
		},
	}

	cmd.Flags().StringVar(&ecosystem, "ecosystem", "", "Limit to ecosystem")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress output")

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
	case "markdown":
		return report.WriteMarkdown(ctx, w, result)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}
