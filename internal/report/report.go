// Package report renders check results for humans and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/patrikfejda/scim-conformance/internal/check"
)

// Summary aggregates results for the JSON report and the exit decision.
type Summary struct {
	Target  string         `json:"target"`
	Results []check.Result `json:"results"`
	Passed  int            `json:"passed"`
	Failed  int            `json:"failed"`
	Skipped int            `json:"skipped"`
	Errored int            `json:"errored"`
	// RequiredFailures counts failed or errored checks with severity
	// "required" — the number that decides the exit code.
	RequiredFailures int `json:"requiredFailures"`
}

// Summarize computes counts over results.
func Summarize(target string, results []check.Result) Summary {
	s := Summary{Target: target, Results: results}
	for _, r := range results {
		switch r.Status {
		case check.Pass:
			s.Passed++
		case check.Fail:
			s.Failed++
		case check.Skip:
			s.Skipped++
		case check.Error:
			s.Errored++
		}
		if (r.Status == check.Fail || r.Status == check.Error) && r.Severity == check.Required {
			s.RequiredFailures++
		}
	}
	return s
}

// WriteJSON emits the machine-readable report.
func (s Summary) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// WriteText emits the human-readable report.
func (s Summary) WriteText(w io.Writer) error {
	for _, r := range s.Results {
		line := fmt.Sprintf("%-5s %-9s %-28s %s", statusMark(r.Status), r.Severity, r.ID, r.Description)
		if r.Detail != "" {
			line += "\n      " + r.Detail
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "\n%s: %d passed, %d failed, %d skipped, %d errored (%d required failures)\n",
		s.Target, s.Passed, s.Failed, s.Skipped, s.Errored, s.RequiredFailures)
	return err
}

func statusMark(s check.Status) string {
	switch s {
	case check.Pass:
		return "PASS"
	case check.Fail:
		return "FAIL"
	case check.Skip:
		return "SKIP"
	default:
		return "ERR"
	}
}
