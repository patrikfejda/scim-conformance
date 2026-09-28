// Package check contains the conformance checks and the machinery to run
// them against a live SCIM service provider.
package check

import (
	"context"

	"github.com/patrikfejda/scim-conformance/internal/scim"
)

// Status is the outcome of one check.
type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
	// Skip means the precondition for the check was not met (e.g. the
	// server declares PATCH unsupported), which is not a failure.
	Skip Status = "skip"
	// Error means the check could not run at all (network failure, etc.).
	Error Status = "error"
)

// Severity distinguishes hard RFC requirements from checks where the spec
// is ambiguous or widely violated in practice. Advisory failures never
// affect the exit code; they feed the deviation corpus.
type Severity string

const (
	Required Severity = "required"
	Advisory Severity = "advisory"
)

// Result is one check outcome, self-describing for reports.
type Result struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Reference   string   `json:"reference"` // RFC + section the check encodes
	Severity    Severity `json:"severity"`
	Status      Status   `json:"status"`
	Detail      string   `json:"detail,omitempty"`
}

// Runner executes check groups against one target.
type Runner struct {
	Client *scim.Client
	// UserNameSuffix makes created test users unique per run; injected so
	// tests stay deterministic.
	UserNameSuffix string
}

// RunAll executes every implemented check group in order and returns the
// combined results. Discovery runs first because later groups consult
// ServiceProviderConfig capabilities.
func (r *Runner) RunAll(ctx context.Context) []Result {
	results, caps := r.Discovery(ctx)
	results = append(results, r.UserLifecycle(ctx, caps)...)
	return results
}
