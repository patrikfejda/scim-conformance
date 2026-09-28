// scim-conformance is a vendor-neutral black-box conformance runner for
// SCIM 2.0 service providers (RFC 7643/7644).
//
// Usage:
//
//	scim-conformance --base-url https://idp.example/scim/v2 --token $TOKEN
//	scim-conformance --base-url http://localhost:8080/scim/v2 --basic admin:admin --json
//
// Exit code is non-zero when any required check fails or errors.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/patrikfejda/scim-conformance/internal/check"
	"github.com/patrikfejda/scim-conformance/internal/report"
	"github.com/patrikfejda/scim-conformance/internal/scim"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("scim-conformance", flag.ContinueOnError)
	baseURL := fs.String("base-url", "", "SCIM base URL, e.g. https://idp.example/scim/v2 (required)")
	token := fs.String("token", "", "bearer token (or set SCIM_TOKEN)")
	basic := fs.String("basic", "", "basic auth as user:pass")
	jsonOut := fs.Bool("json", false, "emit a JSON report instead of text")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall run timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *baseURL == "" {
		fmt.Fprintln(os.Stderr, "error: --base-url is required")
		fs.Usage()
		return 2
	}
	if *token == "" {
		*token = os.Getenv("SCIM_TOKEN")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	runner := &check.Runner{
		Client:         scim.NewClient(*baseURL, *token, *basic),
		UserNameSuffix: fmt.Sprintf("%d", time.Now().UnixNano()),
	}
	summary := report.Summarize(*baseURL, runner.RunAll(ctx))

	var err error
	if *jsonOut {
		err = summary.WriteJSON(os.Stdout)
	} else {
		err = summary.WriteText(os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error writing report:", err)
		return 2
	}
	if summary.RequiredFailures > 0 {
		return 1
	}
	return 0
}
