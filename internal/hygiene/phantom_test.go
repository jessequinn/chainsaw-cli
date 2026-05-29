package hygiene

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestCheckPhantom_detects_undeclared(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{"express":"*"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	jsCode := `const lodash = require('lodash');\nconst express = require('express');`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(jsCode), 0644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	findings := CheckPhantom(dir)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Component.Name != "lodash" {
		t.Errorf("component.name = %q, want %q", findings[0].Component.Name, "lodash")
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("severity = %q, want %q", findings[0].Severity, models.SeverityMedium)
	}
	if findings[0].Source != "phantom" {
		t.Errorf("source = %q, want %q", findings[0].Source, "phantom")
	}
}

func TestCheckPhantom_ignores_declared(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{"lodash":"*","express":"*"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	jsCode := `const lodash = require('lodash');\nconst express = require('express');`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(jsCode), 0644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	findings := CheckPhantom(dir)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestCheckPhantom_ignores_relative(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	jsCode := `const local = require('./local');\nconst util = require('../util');`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(jsCode), 0644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	findings := CheckPhantom(dir)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for relative imports, got %d", len(findings))
	}
}

func TestCheckPhantom_ignores_builtins(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	jsCode := `const fs = require('fs');\nconst path = require('path');\nconst http = require('http');`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(jsCode), 0644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	findings := CheckPhantom(dir)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for builtin modules, got %d", len(findings))
	}
}

func TestCheckPhantom_scoped_package(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	jsCode := `import { Component } from '@org/pkg/sub';\nconst lib = require('@angular/core/sub');`
	if err := os.WriteFile(filepath.Join(dir, "app.ts"), []byte(jsCode), 0644); err != nil {
		t.Fatalf("failed to write app.ts: %v", err)
	}

	findings := CheckPhantom(dir)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for scoped packages, got %d", len(findings))
	}

	pkgNames := make(map[string]bool)
	for _, f := range findings {
		pkgNames[f.Component.Name] = true
	}
	if !pkgNames["@org/pkg"] {
		t.Errorf("expected finding for @org/pkg, got: %v", pkgNames)
	}
	if !pkgNames["@angular/core"] {
		t.Errorf("expected finding for @angular/core, got: %v", pkgNames)
	}
}

func TestCheckPhantom_no_package_json(t *testing.T) {
	dir := t.TempDir()
	jsCode := `const lodash = require('lodash');`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(jsCode), 0644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	findings := CheckPhantom(dir)
	if findings != nil {
		t.Errorf("expected nil findings when no package.json, got %d findings", len(findings))
	}
}

func TestCheckPhantom_multiple_files(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{"express":"*"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	// Create multiple source files with different imports
	file1Code := `const lodash = require('lodash');`
	if err := os.WriteFile(filepath.Join(dir, "file1.js"), []byte(file1Code), 0644); err != nil {
		t.Fatalf("failed to write file1.js: %v", err)
	}

	file2Code := `import axios from 'axios';`
	if err := os.WriteFile(filepath.Join(dir, "file2.ts"), []byte(file2Code), 0644); err != nil {
		t.Fatalf("failed to write file2.ts: %v", err)
	}

	findings := CheckPhantom(dir)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	pkgNames := make(map[string]bool)
	for _, f := range findings {
		pkgNames[f.Component.Name] = true
	}
	if !pkgNames["lodash"] {
		t.Errorf("expected finding for lodash, got: %v", pkgNames)
	}
	if !pkgNames["axios"] {
		t.Errorf("expected finding for axios, got: %v", pkgNames)
	}
}

func TestCheckPhantom_skips_node_modules(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	// Create source file in root
	rootCode := `const express = require('express');`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(rootCode), 0644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	// Create nested source file in node_modules (should be skipped)
	nodeModulesDir := filepath.Join(dir, "node_modules", "lodash")
	if err := os.MkdirAll(nodeModulesDir, 0755); err != nil {
		t.Fatalf("failed to create node_modules: %v", err)
	}
	nmCode := `const internal = require('internal-lib');`
	if err := os.WriteFile(filepath.Join(nodeModulesDir, "index.js"), []byte(nmCode), 0644); err != nil {
		t.Fatalf("failed to write node_modules file: %v", err)
	}

	findings := CheckPhantom(dir)
	// Should only find express from root, not internal-lib from node_modules
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Component.Name != "express" {
		t.Errorf("component.name = %q, want %q", findings[0].Component.Name, "express")
	}
}

func TestCheckPhantom_deduplicates(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	// Same package imported multiple times
	code := `
const lodash = require('lodash');
const util = require('lodash');
import { map } from 'lodash';
`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(code), 0644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	findings := CheckPhantom(dir)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (deduplicated), got %d", len(findings))
	}
	if findings[0].Component.Name != "lodash" {
		t.Errorf("component.name = %q, want %q", findings[0].Component.Name, "lodash")
	}
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		name     string
		module   string
		expected string
	}{
		{
			name:     "simple_package",
			module:   "lodash",
			expected: "lodash",
		},
		{
			name:     "simple_with_subpath",
			module:   "lodash/fp",
			expected: "lodash",
		},
		{
			name:     "nested_subpath",
			module:   "lodash/util/map/deep",
			expected: "lodash",
		},
		{
			name:     "scoped_package",
			module:   "@org/pkg",
			expected: "@org/pkg",
		},
		{
			name:     "scoped_with_subpath",
			module:   "@org/pkg/sub",
			expected: "@org/pkg",
		},
		{
			name:     "scoped_deep_subpath",
			module:   "@org/pkg/sub/deep/path",
			expected: "@org/pkg",
		},
		{
			name:     "scoped_single_part",
			module:   "@org",
			expected: "@org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPackageName(tt.module)
			if result != tt.expected {
				t.Errorf("extractPackageName(%q) = %q, want %q", tt.module, result, tt.expected)
			}
		})
	}
}

func TestIsNodeBuiltin(t *testing.T) {
	tests := []struct {
		name     string
		module   string
		expected bool
	}{
		{name: "fs", module: "fs", expected: true},
		{name: "path", module: "path", expected: true},
		{name: "http", module: "http", expected: true},
		{name: "https", module: "https", expected: true},
		{name: "node_http", module: "node:http", expected: true},
		{name: "node_fs", module: "node:fs", expected: true},
		{name: "lodash", module: "lodash", expected: false},
		{name: "express", module: "express", expected: false},
		{name: "custom", module: "my-custom-lib", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNodeBuiltin(tt.module)
			if result != tt.expected {
				t.Errorf("isNodeBuiltin(%q) = %v, want %v", tt.module, result, tt.expected)
			}
		})
	}
}

func TestCheckPhantom_dev_dependencies(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{
		"dependencies":{"express":"*"},
		"devDependencies":{"jest":"*"}
	}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	jsCode := `const jest = require('jest');\nconst express = require('express');\nconst mocha = require('mocha');`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(jsCode), 0644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	findings := CheckPhantom(dir)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Component.Name != "mocha" {
		t.Errorf("component.name = %q, want %q", findings[0].Component.Name, "mocha")
	}
}

func TestParseImports(t *testing.T) {
	dir := t.TempDir()

	// Create a test file with various import styles
	code := `
const lodash = require('lodash');
import { map } from 'underscore';
const express = require('express');
import axios from 'axios';
import * as fs from 'fs';
const { join } = require('path');
`
	filePath := filepath.Join(dir, "test.js")
	if err := os.WriteFile(filePath, []byte(code), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	imports := parseImports(filePath)

	expectedModules := []string{"lodash", "underscore", "express", "axios", "fs", "path"}
	if len(imports) != len(expectedModules) {
		t.Fatalf("expected %d imports, got %d: %v", len(expectedModules), len(imports), imports)
	}

	for i, expected := range expectedModules {
		if imports[i] != expected {
			t.Errorf("import[%d] = %q, want %q", i, imports[i], expected)
		}
	}
}

func TestCheckPhantom_mixed_extensions(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	// .js file
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(`require('lodash')`), 0644); err != nil {
		t.Fatalf("failed to write app.js: %v", err)
	}

	// .ts file
	if err := os.WriteFile(filepath.Join(dir, "app.ts"), []byte(`import 'axios'`), 0644); err != nil {
		t.Fatalf("failed to write app.ts: %v", err)
	}

	// .jsx file
	if err := os.WriteFile(filepath.Join(dir, "App.jsx"), []byte(`import React from 'react'`), 0644); err != nil {
		t.Fatalf("failed to write App.jsx: %v", err)
	}

	// .tsx file
	if err := os.WriteFile(filepath.Join(dir, "App.tsx"), []byte(`import { Component } from '@emotion/react'`), 0644); err != nil {
		t.Fatalf("failed to write App.tsx: %v", err)
	}

	// .mjs file
	if err := os.WriteFile(filepath.Join(dir, "esm.mjs"), []byte(`import fastify from 'fastify'`), 0644); err != nil {
		t.Fatalf("failed to write esm.mjs: %v", err)
	}

	// Ignored: .txt file
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte(`require('ignored')`), 0644); err != nil {
		t.Fatalf("failed to write readme.txt: %v", err)
	}

	findings := CheckPhantom(dir)
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}

	pkgNames := make(map[string]bool)
	for _, f := range findings {
		pkgNames[f.Component.Name] = true
	}

	expectedPkgs := []string{"lodash", "axios", "react", "@emotion/react", "fastify"}
	for _, expected := range expectedPkgs {
		if !pkgNames[expected] {
			t.Errorf("expected finding for %q, got: %v", expected, pkgNames)
		}
	}
}
