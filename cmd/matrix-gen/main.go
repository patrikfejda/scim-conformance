// matrix-gen renders JSON reports produced by scim-conformance --json
// into a static HTML interop matrix.
//
// Usage:
//
//	matrix-gen -o docs/matrix/index.html "Keycloak 26.7.4=docs/matrix/keycloak-26.7.4.json" ...
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/patrikfejda/scim-conformance/internal/matrix"
	"github.com/patrikfejda/scim-conformance/internal/report"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	out := ""
	var entries []matrix.Entry
	for i := 0; i < len(args); i++ {
		if args[i] == "-o" {
			if i+1 >= len(args) {
				return fmt.Errorf("-o needs a path")
			}
			i++
			out = args[i]
			continue
		}
		name, path, ok := strings.Cut(args[i], "=")
		if !ok {
			return fmt.Errorf("argument %q is not in name=report.json form", args[i])
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var s report.Summary
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		entries = append(entries, matrix.Entry{Name: name, Summary: s})
	}
	if out == "" || len(entries) == 0 {
		return fmt.Errorf("usage: matrix-gen -o out.html name=report.json [name=report.json ...]")
	}
	html, err := matrix.RenderHTML(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(out, []byte(html), 0o644)
}
