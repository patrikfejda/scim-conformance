package check

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// cursorCheckIDs are all checks in the RFC 9865 pack, used to emit a
// uniform "not applicable" result set when the server does not advertise
// cursor pagination.
var cursorCheckIDs = []string{
	"rfc9865-no-prevcursor-first",
	"rfc9865-count-ceiling",
	"rfc9865-first-page",
	"rfc9865-follow-cursor",
	"rfc9865-invalid-cursor",
	"rfc9865-count-zero",
}

// CursorPagination runs the RFC 9865 (cursor-based pagination) pack. The
// whole pack is gated on the ServiceProviderConfig advertising
// pagination.cursor == true; if it does not, every check is reported Skip
// (not applicable) rather than Fail, matching how optional SCIM features
// are handled. When the gate passes, a small set of users is seeded so the
// page-walking checks have something to page over, and removed afterwards.
func (r *Runner) CursorPagination(ctx context.Context) []Result {
	gate := Result{
		ID:          "rfc9865-spc-pagination",
		Description: "ServiceProviderConfig advertises cursor pagination with required boolean cursor/index",
		Reference:   "RFC 9865 §4",
		Severity:    Advisory,
	}
	resp, err := r.Client.Do(ctx, http.MethodGet, "/ServiceProviderConfig", nil)
	if err != nil {
		gate.Status, gate.Detail = Error, err.Error()
		return append([]Result{gate}, skippedCursorPack("ServiceProviderConfig unreachable")...)
	}
	body, jsonErr := resp.JSON()
	if jsonErr != nil {
		gate.Status, gate.Detail = Error, jsonErr.Error()
		return append([]Result{gate}, skippedCursorPack("ServiceProviderConfig not JSON")...)
	}
	pag, ok := body["pagination"].(map[string]any)
	if !ok {
		gate.Status = Skip
		gate.Detail = "no pagination capability advertised (RFC 9865 not supported)"
		return append([]Result{gate}, skippedCursorPack("cursor pagination not advertised")...)
	}
	cursorSupported, cursorIsBool := pag["cursor"].(bool)
	_, indexIsBool := pag["index"].(bool)
	switch {
	case !cursorIsBool || !indexIsBool:
		gate.Status = Fail
		gate.Detail = "pagination.cursor and pagination.index MUST both be booleans (RFC 9865 §4)"
		return append([]Result{gate}, skippedCursorPack("malformed pagination advertisement")...)
	case !cursorSupported:
		gate.Status = Skip
		gate.Detail = "pagination.cursor is false (server does not offer cursor pagination)"
		return append([]Result{gate}, skippedCursorPack("cursor pagination disabled")...)
	}
	gate.Status = Pass

	seeded := r.seedUsers(ctx, 3)
	defer func() {
		for _, id := range seeded {
			r.cleanupResource(ctx, "/Users/", id)
		}
	}()

	results := []Result{gate}
	results = append(results, r.cursorFirstPage(ctx))
	results = append(results, r.cursorNoPrevCursorFirst(ctx))
	results = append(results, r.cursorCountCeiling(ctx))
	results = append(results, r.cursorFollow(ctx, len(seeded)))
	results = append(results, r.cursorInvalid(ctx))
	results = append(results, r.cursorCountZero(ctx))
	return results
}

// seedUsers creates n throwaway users and returns their ids (best effort;
// a short seed is enough for the page-walking checks).
func (r *Runner) seedUsers(ctx context.Context, n int) []string {
	var ids []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("scim-conformance-cursor-%s-%d", r.UserNameSuffix, i)
		id, _, err := r.postUser(ctx, map[string]any{
			"schemas":  []string{urnUser},
			"userName": name,
			"name":     map[string]any{"givenName": "Cursor", "familyName": fmt.Sprintf("Seed%d", i)},
			"emails":   []map[string]any{{"value": name + "@scim-conformance.invalid", "primary": true}},
		})
		if err == nil && id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func (r *Runner) cursorFirstPage(ctx context.Context) Result {
	res := Result{
		ID:          "rfc9865-first-page",
		Description: "first page (count=2, no cursor) returns a ListResponse with at most count resources",
		Reference:   "RFC 9865 §2",
		Severity:    Required,
	}
	body, status, err := r.getList(ctx, "/Users?count=2")
	switch {
	case err != nil:
		res.Status, res.Detail = Error, err.Error()
	case status != http.StatusOK:
		res.Status, res.Detail = Fail, fmt.Sprintf("expected 200, got %d", status)
	case !hasSchema(body, urnListResponse):
		res.Status, res.Detail = Fail, "response is not a ListResponse"
	case len(resourcesOf(body)) > 2:
		res.Status, res.Detail = Fail, fmt.Sprintf("count=2 but %d resources returned", len(resourcesOf(body)))
	default:
		// If more than 2 resources exist in total, nextCursor must be present.
		if total := numberAt(body, "totalResults"); total > 2 {
			if s, _ := body["nextCursor"].(string); s == "" {
				res.Status, res.Detail = Fail, "more results exist but nextCursor is missing/empty"
				return res
			}
		}
		res.Status = Pass
	}
	return res
}

func (r *Runner) cursorNoPrevCursorFirst(ctx context.Context) Result {
	res := Result{
		ID:          "rfc9865-no-prevcursor-first",
		Description: "previousCursor is absent on the first page",
		Reference:   "RFC 9865 §2",
		Severity:    Required,
	}
	body, status, err := r.getList(ctx, "/Users?count=2")
	switch {
	case err != nil:
		res.Status, res.Detail = Error, err.Error()
	case status != http.StatusOK:
		res.Status, res.Detail = Fail, fmt.Sprintf("expected 200, got %d", status)
	default:
		if _, present := body["previousCursor"]; present {
			res.Status, res.Detail = Fail, "previousCursor MUST NOT be returned with the first page"
			return res
		}
		res.Status = Pass
	}
	return res
}

func (r *Runner) cursorCountCeiling(ctx context.Context) Result {
	res := Result{
		ID:          "rfc9865-count-ceiling",
		Description: "count is an upper bound: count=1 returns at most one resource",
		Reference:   "RFC 9865 §2",
		Severity:    Required,
	}
	body, status, err := r.getList(ctx, "/Users?count=1")
	switch {
	case err != nil:
		res.Status, res.Detail = Error, err.Error()
	case status != http.StatusOK:
		res.Status, res.Detail = Fail, fmt.Sprintf("expected 200, got %d", status)
	case len(resourcesOf(body)) > 1:
		res.Status, res.Detail = Fail, fmt.Sprintf("count=1 but %d resources returned", len(resourcesOf(body)))
	default:
		res.Status = Pass
	}
	return res
}

// cursorFollow walks from the first page to the second via nextCursor and
// asserts the two pages do not share resource ids. Needs at least 3
// seeded resources to be meaningful; otherwise it skips.
func (r *Runner) cursorFollow(ctx context.Context, seeded int) Result {
	res := Result{
		ID:          "rfc9865-follow-cursor",
		Description: "following nextCursor yields a distinct next page (no id overlap)",
		Reference:   "RFC 9865 §2",
		Severity:    Required,
	}
	if seeded < 3 {
		res.Status, res.Detail = Skip, "fewer than 3 resources available to page over"
		return res
	}
	first, status, err := r.getList(ctx, "/Users?count=2")
	if err != nil {
		res.Status, res.Detail = Error, err.Error()
		return res
	}
	if status != http.StatusOK {
		res.Status, res.Detail = Fail, fmt.Sprintf("first page expected 200, got %d", status)
		return res
	}
	next, _ := first["nextCursor"].(string)
	if next == "" {
		res.Status, res.Detail = Fail, "nextCursor missing on first page despite >2 resources"
		return res
	}
	second, status, err := r.getList(ctx, "/Users?count=2&cursor="+url.QueryEscape(next))
	if err != nil {
		res.Status, res.Detail = Error, err.Error()
		return res
	}
	if status != http.StatusOK {
		res.Status, res.Detail = Fail, fmt.Sprintf("second page expected 200, got %d", status)
		return res
	}
	firstIDs := idSet(resourcesOf(first))
	for _, r2 := range resourcesOf(second) {
		if obj, ok := r2.(map[string]any); ok {
			if id, _ := obj["id"].(string); id != "" && firstIDs[id] {
				res.Status, res.Detail = Fail, fmt.Sprintf("id %q appears on both pages", id)
				return res
			}
		}
	}
	res.Status = Pass
	return res
}

func (r *Runner) cursorInvalid(ctx context.Context) Result {
	res := Result{
		ID:          "rfc9865-invalid-cursor",
		Description: "a garbage cursor is rejected with 400 scimType invalidCursor",
		Reference:   "RFC 9865 §2.1",
		Severity:    Required,
	}
	body, status, err := r.getList(ctx, "/Users?count=2&cursor=not-a-real-cursor")
	switch {
	case err != nil:
		res.Status, res.Detail = Error, err.Error()
	case status != http.StatusBadRequest:
		res.Status, res.Detail = Fail, fmt.Sprintf("expected 400, got %d", status)
	case !hasSchema(body, urnError):
		res.Status, res.Detail = Fail, "response is not a SCIM error"
	default:
		if st, _ := body["scimType"].(string); st != "invalidCursor" {
			res.Status, res.Detail = Fail, fmt.Sprintf("expected scimType invalidCursor, got %q", st)
			return res
		}
		res.Status = Pass
	}
	return res
}

func (r *Runner) cursorCountZero(ctx context.Context) Result {
	res := Result{
		ID:          "rfc9865-count-zero",
		Description: "count=0 returns metadata only, no resources",
		Reference:   "RFC 9865 §2",
		Severity:    Advisory,
	}
	body, status, err := r.getList(ctx, "/Users?count=0")
	switch {
	case err != nil:
		res.Status, res.Detail = Error, err.Error()
	case status != http.StatusOK:
		res.Status, res.Detail = Fail, fmt.Sprintf("expected 200, got %d", status)
	case len(resourcesOf(body)) != 0:
		res.Status, res.Detail = Fail, fmt.Sprintf("count=0 but %d resources returned", len(resourcesOf(body)))
	default:
		res.Status = Pass
	}
	return res
}

// getList performs a GET and returns the decoded body, status, and error.
func (r *Runner) getList(ctx context.Context, path string) (map[string]any, int, error) {
	resp, err := r.Client.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, err
	}
	body, jsonErr := resp.JSON()
	if jsonErr != nil {
		return nil, resp.StatusCode, nil // non-JSON body: let callers judge by status
	}
	return body, resp.StatusCode, nil
}

func resourcesOf(body map[string]any) []any {
	res, _ := body["Resources"].([]any)
	return res
}

func idSet(resources []any) map[string]bool {
	out := map[string]bool{}
	for _, r := range resources {
		if obj, ok := r.(map[string]any); ok {
			if id, _ := obj["id"].(string); id != "" {
				out[id] = true
			}
		}
	}
	return out
}

func skippedCursorPack(reason string) []Result {
	out := make([]Result, 0, len(cursorCheckIDs))
	for _, id := range cursorCheckIDs {
		sev := Required
		if id == "rfc9865-count-zero" {
			sev = Advisory
		}
		out = append(out, Result{ID: id, Severity: sev, Status: Skip, Detail: reason})
	}
	return out
}
