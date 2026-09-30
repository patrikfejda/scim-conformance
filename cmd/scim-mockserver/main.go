// scim-mockserver runs a mock SCIM 2.0 service provider and grades the
// behaviour of whatever provisioning *client* is pointed at it (e.g.
// keycloak-scim, Entra, Okta, authentik's outbound provider). This is the
// client-testing counterpart to the scim-conformance server runner.
//
// Usage:
//
//	scim-mockserver --addr :8123
//	# point your SCIM client at http://<host>:8123, provision some users,
//	# then hit Ctrl-C to print the client-behaviour report.
//	scim-mockserver --addr :8123 --json   # machine-readable report on exit
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/patrikfejda/scim-conformance/internal/mockserver"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	addr := ":8123"
	jsonOut := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --addr needs a value")
				return 2
			}
			i++
			addr = args[i]
		case "--json":
			jsonOut = true
		default:
			fmt.Fprintf(os.Stderr, "error: unknown argument %q\n", args[i])
			return 2
		}
	}

	server := mockserver.New()
	httpServer := &http.Server{Addr: addr, Handler: server}

	errc := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "scim-mockserver listening on %s — point your SCIM client here, then Ctrl-C for the report\n", addr)
		err := httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	case <-sig:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)

	obs := server.Observations()
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(obs); err != nil {
			fmt.Fprintln(os.Stderr, "error writing report:", err)
			return 1
		}
	} else {
		printReport(obs)
	}
	return 0
}

func printReport(obs []mockserver.Observation) {
	fmt.Println()
	fmt.Println("Client behaviour report")
	fmt.Println("=======================")
	failures := 0
	for _, o := range obs {
		mark := "PASS"
		if !o.OK {
			mark = "FAIL"
			failures++
		}
		line := fmt.Sprintf("%-5s %-9s %s", mark, o.Severity, o.Check)
		if o.Method != "" {
			line += fmt.Sprintf(" [%s %s]", o.Method, o.Path)
		}
		fmt.Println(line)
		if o.Detail != "" && !o.OK {
			fmt.Println("      " + o.Detail)
		}
	}
	fmt.Printf("\n%d observations, %d findings\n", len(obs), failures)
}
