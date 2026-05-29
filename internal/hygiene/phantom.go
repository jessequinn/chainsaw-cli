package hygiene

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

var (
	requireRegex = regexp.MustCompile(`require\s*\(\s*['"]([^./][^'"]+)['"]\s*\)`)
	importRegex  = regexp.MustCompile(`(?:import\s+.*?from\s+|import\s+)['"]([^./][^'"]+)['"]`)
)

// CheckPhantom detects npm packages imported in source code but not listed
// as direct dependencies in package.json.
func CheckPhantom(root string) []models.Finding {
	pkgPath := filepath.Join(root, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil // no package.json, skip
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	// Build set of declared direct dependencies.
	declared := make(map[string]bool)
	for name := range pkg.Dependencies {
		declared[name] = true
	}
	for name := range pkg.DevDependencies {
		declared[name] = true
	}

	// Collect imports from source files.
	imports := collectImports(root)

	// Find phantom dependencies.
	var findings []models.Finding
	seen := make(map[string]bool)
	for _, imp := range imports {
		pkgName := extractPackageName(imp.module)
		if pkgName == "" || declared[pkgName] || seen[pkgName] {
			continue
		}
		if isNodeBuiltin(pkgName) {
			continue
		}
		seen[pkgName] = true

		findings = append(findings, models.Finding{
			ID:       fmt.Sprintf("PHANTOM-%s", pkgName),
			Summary:  fmt.Sprintf("Package %q is imported in %s but not declared in package.json", pkgName, imp.file),
			Severity: models.SeverityMedium,
			Component: models.Component{
				Name:      pkgName,
				Ecosystem: models.EcosystemNpm,
			},
			Source: "phantom",
		})
	}

	return findings
}

type importRef struct {
	module string
	file   string
}

func collectImports(root string) []importRef {
	var imports []importRef

	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip common directories.
		if info.IsDir() {
			name := info.Name()
			if name == "node_modules" || name == ".git" || name == "dist" || name == "build" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".js" && ext != ".ts" && ext != ".jsx" && ext != ".tsx" && ext != ".mjs" && ext != ".cjs" {
			return nil
		}

		fileImports := parseImports(path)
		rel, _ := filepath.Rel(root, path)
		for _, m := range fileImports {
			imports = append(imports, importRef{module: m, file: rel})
		}

		return nil
	})

	return imports
}

func parseImports(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var modules []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		for _, match := range requireRegex.FindAllStringSubmatch(line, -1) {
			if len(match) > 1 {
				modules = append(modules, match[1])
			}
		}
		for _, match := range importRegex.FindAllStringSubmatch(line, -1) {
			if len(match) > 1 {
				modules = append(modules, match[1])
			}
		}
	}

	return modules
}

// extractPackageName extracts the npm package name from an import path.
// Handles scoped packages (@org/pkg) and subpath imports (pkg/sub).
func extractPackageName(module string) string {
	if strings.HasPrefix(module, "@") {
		// Scoped package: @org/pkg/sub → @org/pkg
		parts := strings.SplitN(module, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return module
	}
	// Regular package: pkg/sub → pkg
	parts := strings.SplitN(module, "/", 2)
	return parts[0]
}

func isNodeBuiltin(name string) bool {
	builtins := map[string]bool{
		"assert": true, "buffer": true, "child_process": true, "cluster": true,
		"crypto": true, "dgram": true, "dns": true, "domain": true,
		"events": true, "fs": true, "http": true, "https": true,
		"net": true, "os": true, "path": true, "punycode": true,
		"querystring": true, "readline": true, "stream": true, "string_decoder": true,
		"timers": true, "tls": true, "tty": true, "url": true,
		"util": true, "v8": true, "vm": true, "zlib": true,
		"worker_threads": true, "perf_hooks": true, "async_hooks": true,
		"console": true, "constants": true, "inspector": true, "module": true,
		"process": true, "sys": true, "trace_events": true, "wasi": true,
		"node:fs": true, "node:path": true, "node:crypto": true, "node:http": true,
		"node:https": true, "node:url": true, "node:util": true, "node:stream": true,
		"node:events": true, "node:os": true, "node:child_process": true, "node:net": true,
		"node:buffer": true, "node:assert": true, "node:cluster": true, "node:dns": true,
		"node:readline": true, "node:tls": true, "node:vm": true, "node:zlib": true,
		"node:worker_threads": true, "node:perf_hooks": true, "node:async_hooks": true,
	}
	return builtins[name]
}
