package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// WriteTree writes a dependency tree visualization.
func WriteTree(w io.Writer, components []models.Component) error {
	// Build adjacency map.
	byName := make(map[string]models.Component)
	for _, c := range components {
		key := c.Name + "@" + c.Version
		byName[key] = c
	}

	// Find root components (direct dependencies).
	var roots []models.Component
	for _, c := range components {
		if c.Direct {
			roots = append(roots, c)
		}
	}

	// Sort roots by name for deterministic output.
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].Name < roots[j].Name
	})

	if len(roots) == 0 {
		// If no direct deps marked, show flat list.
		roots = components
		sort.Slice(roots, func(i, j int) bool {
			return roots[i].Name < roots[j].Name
		})
	}

	fmt.Fprintf(w, "Dependency Tree (%d components)\n", len(components))
	fmt.Fprintln(w, strings.Repeat("=", 40))

	seen := make(map[string]bool)
	for i, root := range roots {
		last := i == len(roots)-1
		writeNode(w, root, byName, seen, "", last, 0)
	}

	return nil
}

func writeNode(w io.Writer, comp models.Component, byName map[string]models.Component, seen map[string]bool, prefix string, last bool, depth int) {
	key := comp.Name + "@" + comp.Version

	connector := "├── "
	if last {
		connector = "└── "
	}
	if depth == 0 {
		connector = ""
	}

	marker := ""
	if seen[key] {
		marker = " (circular)"
	}

	fmt.Fprintf(w, "%s%s%s@%s%s\n", prefix, connector, comp.Name, comp.Version, marker)

	if seen[key] || depth > 10 {
		return
	}
	seen[key] = true

	childPrefix := prefix
	if depth > 0 {
		if last {
			childPrefix += "    "
		} else {
			childPrefix += "│   "
		}
	}

	deps := comp.DependsOn
	sort.Strings(deps)
	for i, dep := range deps {
		child, ok := byName[dep]
		if !ok {
			// Dependency not in component list, show as leaf.
			isLast := i == len(deps)-1
			conn := "├── "
			if isLast {
				conn = "└── "
			}
			fmt.Fprintf(w, "%s%s%s\n", childPrefix, conn, dep)
			continue
		}
		writeNode(w, child, byName, seen, childPrefix, i == len(deps)-1, depth+1)
	}
}

// TreeStats returns summary statistics for the dependency tree.
type TreeStats struct {
	TotalComponents int
	DirectDeps      int
	TransitiveDeps  int
	MaxDepth        int
}

// ComputeTreeStats calculates tree statistics from components.
func ComputeTreeStats(components []models.Component) TreeStats {
	stats := TreeStats{TotalComponents: len(components)}
	for _, c := range components {
		if c.Direct {
			stats.DirectDeps++
		} else {
			stats.TransitiveDeps++
		}
	}

	// Compute max depth via BFS.
	byName := make(map[string]models.Component)
	for _, c := range components {
		byName[c.Name+"@"+c.Version] = c
	}

	for _, c := range components {
		if c.Direct {
			d := computeDepth(c, byName, make(map[string]bool), 0)
			if d > stats.MaxDepth {
				stats.MaxDepth = d
			}
		}
	}

	return stats
}

func computeDepth(comp models.Component, byName map[string]models.Component, seen map[string]bool, depth int) int {
	key := comp.Name + "@" + comp.Version
	if seen[key] || depth > 20 {
		return depth
	}
	seen[key] = true

	maxD := depth
	for _, dep := range comp.DependsOn {
		if child, ok := byName[dep]; ok {
			d := computeDepth(child, byName, seen, depth+1)
			if d > maxD {
				maxD = d
			}
		}
	}
	return maxD
}
