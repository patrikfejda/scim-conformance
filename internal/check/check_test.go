package check

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/patrikfejda/scim-conformance/internal/scim"
)

// mockSCIM is a deliberately compliant in-memory SCIM server. Tests break
// individual behaviours via the overrides map to prove each check detects
// its target violation.
type mockSCIM struct {
	mu        sync.Mutex
	users     map[string]map[string]any
	nextID    int
	overrides map[string]http.HandlerFunc // key: "METHOD /path-prefix"
}

func newMockSCIM() *mockSCIM {
	return &mockSCIM{users: map[string]map[string]any{}, overrides: map[string]http.HandlerFunc{}}
}

func writeSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scim.MediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func scimError(w http.ResponseWriter, status int) {
	writeSCIM(w, status, map[string]any{
		"schemas": []string{urnError},
		"status":  fmt.Sprintf("%d", status),
	})
}

func (m *mockSCIM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for key, h := range m.overrides {
		method, prefix, _ := strings.Cut(key, " ")
		if r.Method == method && strings.HasPrefix(r.URL.Path, prefix) {
			h(w, r)
			return
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/ServiceProviderConfig":
		caps := map[string]any{"supported": true}
		writeSCIM(w, 200, map[string]any{
			"schemas": []string{urnServiceProviderConfig},
			"patch":   caps, "filter": map[string]any{"supported": true, "maxResults": 200},
			"bulk": map[string]any{"supported": false}, "sort": caps,
			"changePassword": map[string]any{"supported": false}, "etag": map[string]any{"supported": false},
		})
	case r.Method == http.MethodGet && r.URL.Path == "/Schemas":
		writeSCIM(w, 200, map[string]any{
			"schemas":      []string{urnListResponse},
			"totalResults": 1,
			"Resources":    []map[string]any{{"id": urnUser, "name": "User"}},
		})
	case r.Method == http.MethodGet && r.URL.Path == "/ResourceTypes":
		writeSCIM(w, 200, map[string]any{
			"schemas":      []string{urnListResponse},
			"totalResults": 1,
			"Resources":    []map[string]any{{"name": "User", "endpoint": "/Users"}},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/Users":
		var user map[string]any
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			scimError(w, 400)
			return
		}
		m.nextID++
		id := fmt.Sprintf("u%d", m.nextID)
		user["id"] = id
		m.users[id] = user
		writeSCIM(w, 201, user)
	case r.Method == http.MethodGet && r.URL.Path == "/Users":
		m.listUsers(w, r)
	case strings.HasPrefix(r.URL.Path, "/Users/"):
		m.userByID(w, r, strings.TrimPrefix(r.URL.Path, "/Users/"))
	default:
		scimError(w, 404)
	}
}

func (m *mockSCIM) listUsers(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	var matches []map[string]any
	for _, u := range m.users {
		if filter == "" || strings.Contains(filter, fmt.Sprintf("%q", u["userName"])) {
			matches = append(matches, u)
		}
	}
	writeSCIM(w, 200, map[string]any{
		"schemas": []string{urnListResponse}, "totalResults": len(matches), "Resources": matches,
	})
}

func (m *mockSCIM) userByID(w http.ResponseWriter, r *http.Request, id string) {
	user, ok := m.users[id]
	if !ok {
		scimError(w, 404)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeSCIM(w, 200, user)
	case http.MethodPut:
		var replacement map[string]any
		if err := json.NewDecoder(r.Body).Decode(&replacement); err != nil {
			scimError(w, 400)
			return
		}
		replacement["id"] = id
		m.users[id] = replacement
		writeSCIM(w, 200, replacement)
	case http.MethodPatch:
		var op struct {
			Operations []struct {
				Op, Path string
				Value    any
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&op); err != nil {
			scimError(w, 400)
			return
		}
		for _, o := range op.Operations {
			if strings.EqualFold(o.Op, "replace") {
				user[o.Path] = o.Value
			}
		}
		writeSCIM(w, 200, user)
	case http.MethodDelete:
		delete(m.users, id)
		w.WriteHeader(204)
	default:
		scimError(w, 400)
	}
}

func runAll(t *testing.T, handler http.Handler) []Result {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	runner := &Runner{Client: scim.NewClient(srv.URL, "", ""), UserNameSuffix: "test"}
	return runner.RunAll(context.Background())
}

func byID(t *testing.T, results []Result, id string) Result {
	t.Helper()
	for _, r := range results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no result with id %q in %v", id, results)
	return Result{}
}

func TestCompliantServerPassesAllRequiredChecks(t *testing.T) {
	results := runAll(t, newMockSCIM())
	if len(results) < 12 {
		t.Fatalf("expected at least 12 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Severity == Required && r.Status != Pass {
			t.Errorf("check %s: expected pass, got %s (%s)", r.ID, r.Status, r.Detail)
		}
	}
}

func TestMissingErrorSchemaIsDetected(t *testing.T) {
	m := newMockSCIM()
	m.overrides["GET /Users/scim-conformance-does-not-exist"] = func(w http.ResponseWriter, r *http.Request) {
		// 404 with a plain (non-SCIM) error body — a common real-world deviation.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error": "not found"}`))
	}
	res := byID(t, runAll(t, m), "user-get-notfound")
	if res.Status != Fail {
		t.Fatalf("expected fail, got %s (%s)", res.Status, res.Detail)
	}
}

func TestWrongCreateStatusIsDetected(t *testing.T) {
	m := newMockSCIM()
	m.overrides["POST /Users"] = func(w http.ResponseWriter, r *http.Request) {
		writeSCIM(w, 200, map[string]any{"id": "u1", "userName": "x"}) // 200 instead of 201
	}
	results := runAll(t, m)
	if res := byID(t, results, "user-create"); res.Status != Fail {
		t.Fatalf("expected fail, got %s (%s)", res.Status, res.Detail)
	}
	// Dependent checks must be skipped, not failed.
	if res := byID(t, results, "user-delete"); res.Status != Skip {
		t.Fatalf("expected dependent check to skip, got %s", res.Status)
	}
}

func TestPatchSkippedWhenUnsupported(t *testing.T) {
	m := newMockSCIM()
	m.overrides["GET /ServiceProviderConfig"] = func(w http.ResponseWriter, r *http.Request) {
		unsupported := map[string]any{"supported": false}
		writeSCIM(w, 200, map[string]any{
			"schemas": []string{urnServiceProviderConfig},
			"patch":   unsupported, "filter": map[string]any{"supported": true},
			"bulk": unsupported, "sort": unsupported, "changePassword": unsupported, "etag": unsupported,
		})
	}
	res := byID(t, runAll(t, m), "user-patch-replace")
	if res.Status != Skip {
		t.Fatalf("expected skip, got %s (%s)", res.Status, res.Detail)
	}
}

func TestPlainJSONContentTypeIsAdvisoryFinding(t *testing.T) {
	m := newMockSCIM()
	m.overrides["GET /ServiceProviderConfig"] = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schemas": []string{urnServiceProviderConfig},
			"patch":   map[string]any{"supported": true}, "filter": map[string]any{"supported": true},
			"bulk": map[string]any{"supported": false}, "sort": map[string]any{"supported": false},
			"changePassword": map[string]any{"supported": false}, "etag": map[string]any{"supported": false},
		})
	}
	res := byID(t, runAll(t, m), "discovery-spconfig-mediatype")
	if res.Status != Fail || res.Severity != Advisory {
		t.Fatalf("expected advisory fail, got %s/%s", res.Severity, res.Status)
	}
}
