package check

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// UserLifecycle exercises one user through create → read → filter →
// replace → patch → delete and asserts the RFC 7644 behaviour at each
// step. Steps after a failed create are skipped rather than reported as
// cascading failures.
func (r *Runner) UserLifecycle(ctx context.Context, caps Capabilities) []Result {
	var results []Result
	if !caps.Reachable {
		return results
	}

	userName := "scim-conformance-" + r.UserNameSuffix
	userID, createResults := r.createUser(ctx, userName)
	results = append(results, createResults...)
	if userID == "" {
		return append(results, skippedLifecycle("user create failed")...)
	}

	results = append(results, r.getUser(ctx, userID, userName))
	results = append(results, r.getMissingUser(ctx))
	results = append(results, r.filterUser(ctx, userName, caps))
	results = append(results, r.replaceUser(ctx, userID, userName))
	results = append(results, r.patchUser(ctx, userID, caps))
	results = append(results, r.deleteUser(ctx, userID)...)
	return results
}

func (r *Runner) createUser(ctx context.Context, userName string) (string, []Result) {
	res := Result{
		ID:          "user-create",
		Description: "POST /Users with a minimal user returns 201 and an id",
		Reference:   "RFC 7644 §3.3",
		Severity:    Required,
	}
	payload := map[string]any{
		"schemas":  []string{urnUser},
		"userName": userName,
	}
	resp, err := r.Client.Do(ctx, http.MethodPost, "/Users", payload)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return "", []Result{res}
	}
	body, jsonErr := resp.JSON()
	switch {
	case resp.StatusCode != http.StatusCreated:
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 201, got %d (body: %.200s)", resp.StatusCode, resp.Body)
	case jsonErr != nil:
		res.Status = Fail
		res.Detail = jsonErr.Error()
	default:
		if id, _ := body["id"].(string); id != "" {
			res.Status = Pass
			return id, []Result{res, checkContentType("user-create-mediatype", resp.ContentType)}
		}
		res.Status = Fail
		res.Detail = "201 response has no id attribute"
	}
	return "", []Result{res}
}

func (r *Runner) getUser(ctx context.Context, id, userName string) Result {
	res := Result{
		ID:          "user-get",
		Description: "GET /Users/{id} returns the created user with matching userName",
		Reference:   "RFC 7644 §3.4.1",
		Severity:    Required,
	}
	resp, err := r.Client.Do(ctx, http.MethodGet, "/Users/"+url.PathEscape(id), nil)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return res
	}
	body, jsonErr := resp.JSON()
	switch {
	case resp.StatusCode != http.StatusOK:
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 200, got %d", resp.StatusCode)
	case jsonErr != nil:
		res.Status = Fail
		res.Detail = jsonErr.Error()
	case body["userName"] != userName:
		res.Status = Fail
		res.Detail = fmt.Sprintf("userName mismatch: got %v", body["userName"])
	default:
		res.Status = Pass
	}
	return res
}

func (r *Runner) getMissingUser(ctx context.Context) Result {
	res := Result{
		ID:          "user-get-notfound",
		Description: "GET on a nonexistent user returns 404 with a SCIM error body",
		Reference:   "RFC 7644 §3.12",
		Severity:    Required,
	}
	resp, err := r.Client.Do(ctx, http.MethodGet, "/Users/scim-conformance-does-not-exist", nil)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return res
	}
	body, jsonErr := resp.JSON()
	switch {
	case resp.StatusCode != http.StatusNotFound:
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 404, got %d", resp.StatusCode)
	case jsonErr != nil:
		res.Status = Fail
		res.Detail = "404 body is not a JSON object: " + jsonErr.Error()
	case !hasSchema(body, urnError):
		res.Status = Fail
		res.Detail = fmt.Sprintf("error body lacks the %s schema", urnError)
	default:
		res.Status = Pass
	}
	return res
}

func (r *Runner) filterUser(ctx context.Context, userName string, caps Capabilities) Result {
	res := Result{
		ID:          "user-filter-eq",
		Description: `GET /Users?filter=userName eq "..." returns a ListResponse containing the user`,
		Reference:   "RFC 7644 §3.4.2.2",
		Severity:    Required,
	}
	if !caps.FilterSupported {
		res.Status = Skip
		res.Detail = "server declares filter.supported=false"
		return res
	}
	query := url.QueryEscape(fmt.Sprintf("userName eq %q", userName))
	resp, err := r.Client.Do(ctx, http.MethodGet, "/Users?filter="+query, nil)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return res
	}
	body, jsonErr := resp.JSON()
	switch {
	case resp.StatusCode != http.StatusOK:
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 200, got %d", resp.StatusCode)
	case jsonErr != nil:
		res.Status = Fail
		res.Detail = jsonErr.Error()
	case !hasSchema(body, urnListResponse):
		res.Status = Fail
		res.Detail = "response is not a ListResponse"
	case numberAt(body, "totalResults") != 1:
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected totalResults 1, got %v", body["totalResults"])
	default:
		res.Status = Pass
	}
	return res
}

func (r *Runner) replaceUser(ctx context.Context, id, userName string) Result {
	res := Result{
		ID:          "user-replace-put",
		Description: "PUT /Users/{id} replaces the user and returns 200 with the new state",
		Reference:   "RFC 7644 §3.5.1",
		Severity:    Required,
	}
	displayName := "SCIM Conformance (updated)"
	payload := map[string]any{
		"schemas":     []string{urnUser},
		"id":          id,
		"userName":    userName,
		"displayName": displayName,
	}
	resp, err := r.Client.Do(ctx, http.MethodPut, "/Users/"+url.PathEscape(id), payload)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return res
	}
	body, jsonErr := resp.JSON()
	switch {
	case resp.StatusCode != http.StatusOK:
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 200, got %d", resp.StatusCode)
	case jsonErr != nil:
		res.Status = Fail
		res.Detail = jsonErr.Error()
	case body["displayName"] != displayName:
		res.Status = Fail
		res.Detail = fmt.Sprintf("displayName not applied: got %v", body["displayName"])
	default:
		res.Status = Pass
	}
	return res
}

func (r *Runner) patchUser(ctx context.Context, id string, caps Capabilities) Result {
	res := Result{
		ID:          "user-patch-replace",
		Description: "PATCH /Users/{id} with a replace op is applied (or the server declares PATCH unsupported)",
		Reference:   "RFC 7644 §3.5.2",
		Severity:    Required,
	}
	if !caps.PatchSupported {
		res.Status = Skip
		res.Detail = "server declares patch.supported=false"
		return res
	}
	displayName := "SCIM Conformance (patched)"
	payload := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "path": "displayName", "value": displayName},
		},
	}
	resp, err := r.Client.Do(ctx, http.MethodPatch, "/Users/"+url.PathEscape(id), payload)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return res
	}
	// RFC 7644 §3.5.2 allows 200 with the resource or 204 without it.
	switch resp.StatusCode {
	case http.StatusOK:
		body, jsonErr := resp.JSON()
		if jsonErr != nil {
			res.Status = Fail
			res.Detail = jsonErr.Error()
		} else if body["displayName"] != displayName {
			res.Status = Fail
			res.Detail = fmt.Sprintf("patch not applied: displayName is %v", body["displayName"])
		} else {
			res.Status = Pass
		}
	case http.StatusNoContent:
		res.Status = Pass
		res.Detail = "204 without body (allowed)"
	default:
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 200 or 204, got %d", resp.StatusCode)
	}
	return res
}

func (r *Runner) deleteUser(ctx context.Context, id string) []Result {
	del := Result{
		ID:          "user-delete",
		Description: "DELETE /Users/{id} returns 204",
		Reference:   "RFC 7644 §3.6",
		Severity:    Required,
	}
	resp, err := r.Client.Do(ctx, http.MethodDelete, "/Users/"+url.PathEscape(id), nil)
	if err != nil {
		del.Status = Error
		del.Detail = err.Error()
		return []Result{del}
	}
	if resp.StatusCode != http.StatusNoContent {
		del.Status = Fail
		del.Detail = fmt.Sprintf("expected 204, got %d", resp.StatusCode)
		return []Result{del}
	}
	del.Status = Pass

	gone := Result{
		ID:          "user-delete-verified",
		Description: "GET after DELETE returns 404",
		Reference:   "RFC 7644 §3.6",
		Severity:    Required,
	}
	resp, err = r.Client.Do(ctx, http.MethodGet, "/Users/"+url.PathEscape(id), nil)
	switch {
	case err != nil:
		gone.Status = Error
		gone.Detail = err.Error()
	case resp.StatusCode != http.StatusNotFound:
		gone.Status = Fail
		gone.Detail = fmt.Sprintf("expected 404, got %d", resp.StatusCode)
	default:
		gone.Status = Pass
	}
	return []Result{del, gone}
}

// skippedLifecycle marks the dependent lifecycle checks as skipped when
// the initial create failed, so reports stay complete and honest.
func skippedLifecycle(reason string) []Result {
	ids := []string{"user-get", "user-get-notfound", "user-filter-eq", "user-replace-put", "user-patch-replace", "user-delete", "user-delete-verified"}
	out := make([]Result, 0, len(ids))
	for _, id := range ids {
		out = append(out, Result{ID: id, Severity: Required, Status: Skip, Detail: reason})
	}
	return out
}

// numberAt reads body[field] as an integer; JSON numbers decode as float64.
func numberAt(body map[string]any, field string) int {
	val, _ := body[field].(float64)
	return int(val)
}
