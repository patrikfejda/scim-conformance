package matrix

import (
	"strings"
	"testing"

	"github.com/patrikfejda/scim-conformance/internal/check"
	"github.com/patrikfejda/scim-conformance/internal/report"
)

func TestRenderHTML(t *testing.T) {
	entries := []Entry{
		{
			Name: "server-a",
			Summary: report.Summary{
				Target: "http://a.example",
				Results: []check.Result{
					{ID: "c1", Description: "check one", Reference: "RFC 7644 §1", Severity: check.Required, Status: check.Pass},
					{ID: "c2", Description: "check two", Reference: "RFC 7644 §2", Severity: check.Advisory, Status: check.Fail, Detail: "broken thing"},
				},
			},
		},
		{
			Name: "server-b",
			Summary: report.Summary{
				Target: "http://b.example",
				Results: []check.Result{
					{ID: "c1", Description: "check one", Reference: "RFC 7644 §1", Severity: check.Required, Status: check.Pass},
					// c2 missing: must render as a gap, not crash
				},
			},
		},
	}
	html, err := RenderHTML(entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"server-a", "server-b", // column headers
		"c1", "check two", "RFC 7644 §2", // row content
		"broken thing",      // failure detail surfaces
		`class="cell pass"`, // status classes
		`class="cell fail"`, // status classes
		`class="cell none"`, // missing result gap
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML missing %q", want)
		}
	}
}
