package mockserver

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/patrikfejda/scim-conformance/internal/scim"
)

const maxBody = 1 << 20

func decodeBody(r *http.Request) (map[string]any, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return nil, err
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, err
	}
	return body, nil
}

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

// resourceURN reports the core schema urn for a resource store by identity.
func resourceURN(store map[string]map[string]any) string {
	// The two stores are distinguished by the caller; this helper exists
	// so PUT validation knows which schema to expect. We infer from a
	// sample resource, defaulting to User.
	for _, res := range store {
		if hasSchema(res, urnGroup) {
			return urnGroup
		}
		return urnUser
	}
	return urnUser
}

func writeSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scim.MediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int) {
	writeSCIM(w, status, map[string]any{
		"schemas": []string{urnErrorResp},
		"status":  strconv.Itoa(status),
	})
}

func serviceProviderConfig() map[string]any {
	on := map[string]any{"supported": true}
	off := map[string]any{"supported": false}
	return map[string]any{
		"schemas":        []string{urnSPConfig},
		"patch":          on,
		"filter":         map[string]any{"supported": true, "maxResults": 200},
		"bulk":           off,
		"sort":           off,
		"changePassword": off,
		"etag":           off,
		"authenticationSchemes": []map[string]any{
			{"type": "oauthbearertoken", "name": "OAuth Bearer Token"},
		},
	}
}

func emptyList() map[string]any {
	return map[string]any{
		"schemas":      []string{urnListResp},
		"totalResults": 0,
		"Resources":    []any{},
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
