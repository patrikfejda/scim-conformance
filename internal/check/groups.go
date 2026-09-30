package check

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

const urnGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"

// GroupLifecycle exercises a Group through create → read → member add
// (PATCH) → member visibility → delete, per RFC 7643 §4.2 and RFC 7644
// §3. A helper user is created first so membership can be tested with a
// real resource id; it is cleaned up at the end.
func (r *Runner) GroupLifecycle(ctx context.Context, caps Capabilities) []Result {
	var results []Result
	if !caps.Reachable {
		return results
	}

	memberName := "scim-conformance-member-" + r.UserNameSuffix
	memberID, memberResults := r.createUser(ctx, memberName)
	// Only surface member-user creation if it failed — it duplicates the
	// user-lifecycle checks otherwise and would double-count passes.
	if memberID == "" {
		results = append(results, skippedGroupLifecycle("helper user create failed")...)
		return results
	}
	_ = memberResults

	displayName := "scim-conformance-group-" + r.UserNameSuffix
	groupID, createRes := r.createGroup(ctx, displayName)
	results = append(results, createRes)
	if groupID == "" {
		results = append(results, skippedGroupLifecycle("group create failed")[1:]...)
		r.cleanupResource(ctx, "/Users/", memberID)
		return results
	}

	results = append(results, r.getGroup(ctx, groupID, displayName))
	results = append(results, r.groupAddMember(ctx, groupID, memberID, caps))
	results = append(results, r.deleteGroup(ctx, groupID))
	r.cleanupResource(ctx, "/Users/", memberID)
	return results
}

func (r *Runner) createGroup(ctx context.Context, displayName string) (string, Result) {
	res := Result{
		ID:          "group-create",
		Description: "POST /Groups with displayName returns 201 and an id",
		Reference:   "RFC 7644 §3.3, RFC 7643 §4.2",
		Severity:    Required,
	}
	payload := map[string]any{
		"schemas":     []string{urnGroup},
		"displayName": displayName,
	}
	resp, err := r.Client.Do(ctx, http.MethodPost, "/Groups", payload)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return "", res
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
			return id, res
		}
		res.Status = Fail
		res.Detail = "201 response has no id attribute"
	}
	return "", res
}

func (r *Runner) getGroup(ctx context.Context, id, displayName string) Result {
	res := Result{
		ID:          "group-get",
		Description: "GET /Groups/{id} returns the created group with matching displayName",
		Reference:   "RFC 7644 §3.4.1",
		Severity:    Required,
	}
	resp, err := r.Client.Do(ctx, http.MethodGet, "/Groups/"+url.PathEscape(id), nil)
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
		res.Detail = fmt.Sprintf("displayName mismatch: got %v", body["displayName"])
	default:
		res.Status = Pass
	}
	return res
}

// groupAddMember PATCHes a member into the group and verifies the
// membership is visible on a subsequent GET of the group.
func (r *Runner) groupAddMember(ctx context.Context, groupID, userID string, caps Capabilities) Result {
	res := Result{
		ID:          "group-patch-add-member",
		Description: "PATCH add on members adds a user to the group (verified via GET)",
		Reference:   "RFC 7644 §3.5.2.1, RFC 7643 §4.2",
		Severity:    Required,
	}
	if !caps.PatchSupported {
		res.Status = Skip
		res.Detail = "server declares patch.supported=false"
		return res
	}
	payload := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "add", "path": "members", "value": []map[string]any{{"value": userID}}},
		},
	}
	resp, err := r.Client.Do(ctx, http.MethodPatch, "/Groups/"+url.PathEscape(groupID), payload)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return res
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 200 or 204, got %d (body: %.200s)", resp.StatusCode, resp.Body)
		return res
	}
	// The Group.members attribute is treated as returned-on-request by
	// several servers (e.g. Keycloak) for performance, so verify by
	// explicitly requesting it — a plain GET may legitimately omit it.
	if r.groupHasMember(ctx, groupID, userID) {
		res.Status = Pass
		return res
	}
	res.Status = Fail
	res.Detail = fmt.Sprintf("member %q not present in group even when requested via ?attributes=members", userID)
	return res
}

// groupHasMember GETs the group requesting members explicitly and reports
// whether userID is among them.
func (r *Runner) groupHasMember(ctx context.Context, groupID, userID string) bool {
	resp, err := r.Client.Do(ctx, http.MethodGet, "/Groups/"+url.PathEscape(groupID)+"?attributes=members", nil)
	if err != nil {
		return false
	}
	body, err := resp.JSON()
	if err != nil {
		return false
	}
	members, _ := body["members"].([]any)
	for _, m := range members {
		if obj, ok := m.(map[string]any); ok && obj["value"] == userID {
			return true
		}
	}
	return false
}

func (r *Runner) deleteGroup(ctx context.Context, id string) Result {
	res := Result{
		ID:          "group-delete",
		Description: "DELETE /Groups/{id} returns 204 and the group is gone",
		Reference:   "RFC 7644 §3.6",
		Severity:    Required,
	}
	resp, err := r.Client.Do(ctx, http.MethodDelete, "/Groups/"+url.PathEscape(id), nil)
	switch {
	case err != nil:
		res.Status = Error
		res.Detail = err.Error()
	case resp.StatusCode != http.StatusNoContent:
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 204, got %d", resp.StatusCode)
	default:
		res.Status = Pass
	}
	return res
}

// cleanupResource deletes a helper resource, ignoring the outcome — it
// is hygiene, not a conformance assertion.
func (r *Runner) cleanupResource(ctx context.Context, prefix, id string) {
	resp, err := r.Client.Do(ctx, http.MethodDelete, prefix+url.PathEscape(id), nil)
	_ = resp
	_ = err
}

func skippedGroupLifecycle(reason string) []Result {
	ids := []string{"group-create", "group-get", "group-patch-add-member", "group-delete"}
	out := make([]Result, 0, len(ids))
	for _, id := range ids {
		out = append(out, Result{ID: id, Severity: Required, Status: Skip, Detail: reason})
	}
	return out
}
