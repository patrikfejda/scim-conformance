package check

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/patrikfejda/scim-conformance/internal/scim"
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
	results = append(results, r.filterNoMatch(ctx, caps))
	results = append(results, r.listAll(ctx))
	results = append(results, r.pagination(ctx)...)
	results = append(results, r.attributesParam(ctx, userID))
	results = append(results, r.replaceUser(ctx, userID, userName)...)
	results = append(results, r.patchUser(ctx, userID, caps))
	results = append(results, r.deleteUser(ctx, userID)...)
	return results
}

// readAttr GETs the user and returns the value of a possibly-nested
// attribute path like "name.givenName" (empty string when absent).
func (r *Runner) readAttr(ctx context.Context, id, path string) (string, error) {
	resp, err := r.Client.Do(ctx, http.MethodGet, "/Users/"+url.PathEscape(id), nil)
	if err != nil {
		return "", err
	}
	body, err := resp.JSON()
	if err != nil {
		return "", err
	}
	var current any = body
	for _, part := range strings.Split(path, ".") {
		obj, ok := current.(map[string]any)
		if !ok {
			return "", nil
		}
		current = obj[part]
	}
	val, _ := current.(string)
	return val, nil
}

// createUser first attempts a spec-minimal user (userName only — the sole
// required core attribute per RFC 7643 §4.1). Servers commonly reject this
// due to their own profile policies, which is a conformance finding but
// should not block the rest of the lifecycle, so a second, enriched
// attempt follows.
func (r *Runner) createUser(ctx context.Context, userName string) (string, []Result) {
	minimal := Result{
		ID:          "user-create-minimal",
		Description: "POST /Users with a spec-minimal user (userName only) is accepted",
		Reference:   "RFC 7643 §4.1, RFC 7644 §3.3",
		Severity:    Advisory,
	}
	id, detail, err := r.postUser(ctx, map[string]any{
		"schemas":  []string{urnUser},
		"userName": userName,
	})
	if err != nil {
		minimal.Status = Error
		minimal.Detail = err.Error()
		return "", []Result{minimal}
	}
	if id != "" {
		minimal.Status = Pass
		created := Result{
			ID:          "user-create",
			Description: "POST /Users returns 201 and an id",
			Reference:   "RFC 7644 §3.3",
			Severity:    Required,
			Status:      Pass,
		}
		return id, []Result{minimal, created}
	}
	minimal.Status = Fail
	minimal.Detail = detail

	created := Result{
		ID:          "user-create",
		Description: "POST /Users returns 201 and an id (enriched user after minimal was rejected)",
		Reference:   "RFC 7644 §3.3",
		Severity:    Required,
	}
	id, detail, err = r.postUser(ctx, map[string]any{
		"schemas":  []string{urnUser},
		"userName": userName,
		"name":     map[string]any{"givenName": "SCIM", "familyName": "Conformance"},
		"emails":   []map[string]any{{"value": userName + "@scim-conformance.invalid", "primary": true}},
	})
	switch {
	case err != nil:
		created.Status = Error
		created.Detail = err.Error()
	case id == "":
		created.Status = Fail
		created.Detail = detail
	default:
		created.Status = Pass
	}
	return id, []Result{minimal, created}
}

// postUser creates a user and returns its id (empty when the server
// refused) plus a failure detail for reports.
func (r *Runner) postUser(ctx context.Context, payload map[string]any) (string, string, error) {
	resp, err := r.Client.Do(ctx, http.MethodPost, "/Users", payload)
	if err != nil {
		return "", "", err
	}
	body, jsonErr := resp.JSON()
	switch {
	case resp.StatusCode != http.StatusCreated:
		return "", fmt.Sprintf("expected 201, got %d (body: %.200s)", resp.StatusCode, resp.Body), nil
	case jsonErr != nil:
		return "", jsonErr.Error(), nil
	}
	id, _ := body["id"].(string)
	if id == "" {
		return "", "201 response has no id attribute", nil
	}
	return id, "", nil
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

func (r *Runner) replaceUser(ctx context.Context, id, userName string) []Result {
	res := Result{
		ID:          "user-replace-put",
		Description: "PUT /Users/{id} replaces the user; the change is visible on a subsequent GET",
		Reference:   "RFC 7644 §3.5.1",
		Severity:    Required,
	}
	familyName := "Conformance-Replaced"
	displayName := "SCIM Conformance (updated)"
	payload := map[string]any{
		"schemas":     []string{urnUser},
		"id":          id,
		"userName":    userName,
		"name":        map[string]any{"givenName": "SCIM", "familyName": familyName},
		"emails":      []map[string]any{{"value": userName + "@scim-conformance.invalid", "primary": true}},
		"displayName": displayName,
	}
	resp, err := r.Client.Do(ctx, http.MethodPut, "/Users/"+url.PathEscape(id), payload)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return []Result{res}
	}
	if resp.StatusCode != http.StatusOK {
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 200, got %d (body: %.200s)", resp.StatusCode, resp.Body)
		return []Result{res}
	}
	stored, err := r.readAttr(ctx, id, "name.familyName")
	switch {
	case err != nil:
		res.Status = Error
		res.Detail = err.Error()
	case stored != familyName:
		res.Status = Fail
		res.Detail = fmt.Sprintf("name.familyName after PUT is %q, want %q", stored, familyName)
	default:
		res.Status = Pass
	}
	return []Result{res, r.replaceReadback(ctx, id, resp, displayName)}
}

// replaceReadback catches servers that echo an attribute in the PUT
// response but silently drop it: whatever the response claims must match
// what a GET returns. RFC 7644 §3.5.1 requires the response to contain
// the resource's actual updated state.
func (r *Runner) replaceReadback(ctx context.Context, id string, putResp *scim.Response, displayName string) Result {
	res := Result{
		ID:          "user-replace-readback",
		Description: "attributes echoed in the PUT response are actually persisted (no silent drops)",
		Reference:   "RFC 7644 §3.5.1",
		Severity:    Advisory,
	}
	body, err := putResp.JSON()
	if err != nil {
		res.Status = Skip
		res.Detail = "PUT response was not a JSON object"
		return res
	}
	echoed, _ := body["displayName"].(string)
	if echoed != displayName {
		// The server did not accept the attribute at all; that is visible
		// in the response, so there is nothing silent to catch here.
		res.Status = Skip
		res.Detail = "displayName not echoed in PUT response"
		return res
	}
	stored, err := r.readAttr(ctx, id, "displayName")
	switch {
	case err != nil:
		res.Status = Error
		res.Detail = err.Error()
	case stored != displayName:
		res.Status = Fail
		res.Detail = fmt.Sprintf("PUT response echoed displayName %q but GET returns %q", displayName, stored)
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
	givenName := "Conformance-Patched"
	payload := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "path": "name.givenName", "value": givenName},
		},
	}
	resp, err := r.Client.Do(ctx, http.MethodPatch, "/Users/"+url.PathEscape(id), payload)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return res
	}
	// RFC 7644 §3.5.2 allows 200 with the resource or 204 without it;
	// either way the change must be visible on a subsequent GET.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 200 or 204, got %d (body: %.200s)", resp.StatusCode, resp.Body)
		return res
	}
	stored, err := r.readAttr(ctx, id, "name.givenName")
	switch {
	case err != nil:
		res.Status = Error
		res.Detail = err.Error()
	case stored != givenName:
		res.Status = Fail
		res.Detail = fmt.Sprintf("name.givenName after PATCH is %q, want %q", stored, givenName)
	default:
		res.Status = Pass
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

// filterNoMatch encodes a common real-world bug: a filter matching
// nothing must yield an empty ListResponse, not an error or 404.
func (r *Runner) filterNoMatch(ctx context.Context, caps Capabilities) Result {
	res := Result{
		ID:          "user-filter-nomatch",
		Description: "a filter matching no users returns 200 with an empty ListResponse (totalResults 0)",
		Reference:   "RFC 7644 §3.4.2.2",
		Severity:    Required,
	}
	if !caps.FilterSupported {
		res.Status = Skip
		res.Detail = "server declares filter.supported=false"
		return res
	}
	query := url.QueryEscape(`userName eq "scim-conformance-no-such-user"`)
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
	case numberAt(body, "totalResults") != 0:
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected totalResults 0, got %v", body["totalResults"])
	default:
		res.Status = Pass
	}
	return res
}

func (r *Runner) listAll(ctx context.Context) Result {
	res := Result{
		ID:          "user-list-all",
		Description: "GET /Users without parameters returns a ListResponse with totalResults and Resources",
		Reference:   "RFC 7644 §3.4.2",
		Severity:    Required,
	}
	resp, err := r.Client.Do(ctx, http.MethodGet, "/Users", nil)
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
	case numberAt(body, "totalResults") < 1:
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected totalResults >= 1 (a test user exists), got %v", body["totalResults"])
	default:
		if _, ok := body["Resources"].([]any); !ok {
			res.Status = Fail
			res.Detail = "Resources attribute missing or not an array"
			return res
		}
		res.Status = Pass
	}
	return res
}

// pagination checks RFC 7644 §3.4.2.4: a paged response MUST include
// startIndex and itemsPerPage, and count is an upper bound on the number
// of returned resources.
func (r *Runner) pagination(ctx context.Context) []Result {
	shape := Result{
		ID:          "user-pagination-shape",
		Description: "a paged request (startIndex=1&count=1) returns startIndex and itemsPerPage",
		Reference:   "RFC 7644 §3.4.2.4",
		Severity:    Required,
	}
	bound := Result{
		ID:          "user-pagination-count-bound",
		Description: "a paged request returns no more resources than count",
		Reference:   "RFC 7644 §3.4.2.4",
		Severity:    Required,
	}
	resp, err := r.Client.Do(ctx, http.MethodGet, "/Users?startIndex=1&count=1", nil)
	if err != nil {
		shape.Status, shape.Detail = Error, err.Error()
		bound.Status, bound.Detail = Skip, "pagination request failed"
		return []Result{shape, bound}
	}
	body, jsonErr := resp.JSON()
	if resp.StatusCode != http.StatusOK || jsonErr != nil {
		shape.Status = Fail
		shape.Detail = fmt.Sprintf("expected 200 with JSON body, got %d", resp.StatusCode)
		bound.Status, bound.Detail = Skip, "pagination request unusable"
		return []Result{shape, bound}
	}
	_, hasStart := body["startIndex"]
	_, hasPer := body["itemsPerPage"]
	if !hasStart || !hasPer {
		shape.Status = Fail
		shape.Detail = fmt.Sprintf("startIndex present: %v, itemsPerPage present: %v", hasStart, hasPer)
	} else {
		shape.Status = Pass
	}
	resources, _ := body["Resources"].([]any)
	if len(resources) > 1 {
		bound.Status = Fail
		bound.Detail = fmt.Sprintf("count=1 but %d resources returned", len(resources))
	} else {
		bound.Status = Pass
	}
	return []Result{shape, bound}
}

// attributesParam checks RFC 7644 §3.4.2.5 attribute selection. Wrong or
// missing support is widespread, so the "others omitted" half is what the
// deviation corpus is for — the check stays advisory.
func (r *Runner) attributesParam(ctx context.Context, id string) Result {
	res := Result{
		ID:          "user-attributes-param",
		Description: "GET /Users/{id}?attributes=userName returns userName and omits unrequested attributes",
		Reference:   "RFC 7644 §3.4.2.5",
		Severity:    Advisory,
	}
	resp, err := r.Client.Do(ctx, http.MethodGet, "/Users/"+url.PathEscape(id)+"?attributes=userName", nil)
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
	case body["userName"] == nil:
		res.Status = Fail
		res.Detail = "requested attribute userName missing from response"
	case body["name"] != nil || body["emails"] != nil:
		res.Status = Fail
		res.Detail = "unrequested attributes (name/emails) present in response"
	default:
		res.Status = Pass
	}
	return res
}

// skippedLifecycle marks the dependent lifecycle checks as skipped when
// the initial create failed, so reports stay complete and honest.
func skippedLifecycle(reason string) []Result {
	ids := []string{"user-get", "user-get-notfound", "user-filter-eq", "user-filter-nomatch", "user-list-all", "user-pagination-shape", "user-pagination-count-bound", "user-attributes-param", "user-replace-put", "user-replace-readback", "user-patch-replace", "user-delete", "user-delete-verified"}
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
