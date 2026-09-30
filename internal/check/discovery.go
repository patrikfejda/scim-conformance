package check

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

const (
	urnServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	urnListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	urnError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	urnUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
)

// Capabilities holds what the server declares about itself; later check
// groups use it to decide what is testable.
type Capabilities struct {
	Reachable       bool
	PatchSupported  bool
	FilterSupported bool
}

// Discovery runs the RFC 7644 §4 discovery-endpoint checks and extracts
// declared capabilities.
func (r *Runner) Discovery(ctx context.Context) ([]Result, Capabilities) {
	var results []Result
	caps := Capabilities{}

	spc := Result{
		ID:          "discovery-spconfig",
		Description: "GET /ServiceProviderConfig returns 200 with the ServiceProviderConfig schema",
		Reference:   "RFC 7644 §4, RFC 7643 §5",
		Severity:    Required,
	}
	resp, err := r.Client.Do(ctx, http.MethodGet, "/ServiceProviderConfig", nil)
	if err != nil {
		spc.Status = Error
		spc.Detail = err.Error()
		return append(results, spc), caps
	}
	caps.Reachable = true
	body, jsonErr := resp.JSON()
	switch {
	case resp.StatusCode != http.StatusOK:
		spc.Status = Fail
		spc.Detail = fmt.Sprintf("expected 200, got %d", resp.StatusCode)
	case jsonErr != nil:
		spc.Status = Fail
		spc.Detail = jsonErr.Error()
	case !hasSchema(body, urnServiceProviderConfig):
		spc.Status = Fail
		spc.Detail = fmt.Sprintf("schemas attribute does not include %s", urnServiceProviderConfig)
	default:
		spc.Status = Pass
		caps.PatchSupported = boolAt(body, "patch", "supported")
		caps.FilterSupported = boolAt(body, "filter", "supported")
	}
	results = append(results, spc)

	results = append(results, checkContentType("discovery-spconfig-mediatype", resp.ContentType))
	results = append(results, r.capabilityDeclarations(body, jsonErr == nil && resp.StatusCode == http.StatusOK)...)
	results = append(results, r.schemasEndpoint(ctx))
	results = append(results, r.resourceTypesEndpoint(ctx))
	return results, caps
}

// capabilityDeclarations verifies the core capability sub-attributes are
// present. etag is checked separately as advisory: RFC 7643 §5 lists it,
// but it is commonly (and forgivably) omitted — even a SCIM RFC author's
// reference server (i2scim) leaves it out, so a hard failure would cry
// wolf.
func (r *Runner) capabilityDeclarations(body map[string]any, parseable bool) []Result {
	core := Result{
		ID:          "discovery-spconfig-capabilities",
		Description: "ServiceProviderConfig declares patch, filter, bulk, sort and changePassword capabilities",
		Reference:   "RFC 7643 §5",
		Severity:    Required,
	}
	etag := Result{
		ID:          "discovery-spconfig-etag",
		Description: "ServiceProviderConfig declares the etag capability",
		Reference:   "RFC 7643 §5",
		Severity:    Advisory,
	}
	if !parseable {
		core.Status, core.Detail = Skip, "ServiceProviderConfig response was not usable"
		etag.Status, etag.Detail = Skip, core.Detail
		return []Result{core, etag}
	}
	var missing []string
	for _, attr := range []string{"patch", "filter", "bulk", "sort", "changePassword"} {
		if _, ok := body[attr].(map[string]any); !ok {
			missing = append(missing, attr)
		}
	}
	if len(missing) > 0 {
		core.Status = Fail
		core.Detail = "missing capability attributes: " + strings.Join(missing, ", ")
	} else {
		core.Status = Pass
	}
	if _, ok := body["etag"].(map[string]any); ok {
		etag.Status = Pass
	} else {
		etag.Status = Fail
		etag.Detail = "etag capability not declared"
	}
	return []Result{core, etag}
}

func (r *Runner) schemasEndpoint(ctx context.Context) Result {
	res := Result{
		ID:          "discovery-schemas",
		Description: "GET /Schemas returns 200 and includes the core User schema",
		Reference:   "RFC 7644 §4",
		Severity:    Required,
	}
	resp, err := r.Client.Do(ctx, http.MethodGet, "/Schemas", nil)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return res
	}
	if resp.StatusCode != http.StatusOK {
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 200, got %d", resp.StatusCode)
		return res
	}
	if !strings.Contains(string(resp.Body), urnUser) {
		res.Status = Fail
		res.Detail = fmt.Sprintf("response does not mention %s", urnUser)
		return res
	}
	res.Status = Pass
	return res
}

func (r *Runner) resourceTypesEndpoint(ctx context.Context) Result {
	res := Result{
		ID:          "discovery-resourcetypes",
		Description: "GET /ResourceTypes returns 200 and includes a User resource type",
		Reference:   "RFC 7644 §4",
		Severity:    Required,
	}
	resp, err := r.Client.Do(ctx, http.MethodGet, "/ResourceTypes", nil)
	if err != nil {
		res.Status = Error
		res.Detail = err.Error()
		return res
	}
	if resp.StatusCode != http.StatusOK {
		res.Status = Fail
		res.Detail = fmt.Sprintf("expected 200, got %d", resp.StatusCode)
		return res
	}
	if !strings.Contains(string(resp.Body), `"User"`) {
		res.Status = Fail
		res.Detail = "response does not include a User resource type"
		return res
	}
	res.Status = Pass
	return res
}

// checkContentType encodes RFC 7644 §3.1: responses use the SCIM media
// type. Plain application/json is so widespread that this stays advisory —
// it is deviation-corpus material, not a hard failure.
func checkContentType(id, contentType string) Result {
	res := Result{
		ID:          id,
		Description: "response Content-Type is application/scim+json",
		Reference:   "RFC 7644 §3.1",
		Severity:    Advisory,
	}
	if strings.HasPrefix(contentType, "application/scim+json") {
		res.Status = Pass
		return res
	}
	res.Status = Fail
	res.Detail = fmt.Sprintf("got %q", contentType)
	return res
}

// hasSchema reports whether the resource's schemas attribute contains urn.
func hasSchema(body map[string]any, urn string) bool {
	schemas, ok := body["schemas"].([]any)
	if !ok {
		return false
	}
	for _, s := range schemas {
		if s == urn {
			return true
		}
	}
	return false
}

// boolAt reads body[section][field] as a bool, defaulting to false.
func boolAt(body map[string]any, section, field string) bool {
	sec, ok := body[section].(map[string]any)
	if !ok {
		return false
	}
	val, _ := sec[field].(bool)
	return val
}
