package check

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/patrikfejda/scim-conformance/internal/scim"
)

// cursorMock is a minimal SCIM server implementing RFC 9865 cursor
// pagination over an in-memory, insertion-ordered user list. It exists to
// exercise the pass paths of the cursor pack; it is deliberately small.
type cursorMock struct {
	mu     sync.Mutex
	order  []string
	users  map[string]map[string]any
	nextID int
	// advertise controls the ServiceProviderConfig pagination block.
	advertiseCursor bool
	malformed       bool // advertise pagination with non-boolean cursor
}

func newCursorMock(advertiseCursor bool) *cursorMock {
	return &cursorMock{users: map[string]map[string]any{}, advertiseCursor: advertiseCursor}
}

func (m *cursorMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/ServiceProviderConfig":
		m.serveSPC(w)
	case r.Method == http.MethodPost && r.URL.Path == "/Users":
		var u map[string]any
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			scimError(w, 400)
			return
		}
		m.nextID++
		id := fmt.Sprintf("cu%d", m.nextID)
		u["id"] = id
		m.users[id] = u
		m.order = append(m.order, id)
		writeSCIM(w, 201, u)
	case r.Method == http.MethodGet && r.URL.Path == "/Users":
		m.serveList(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/Users/"):
		id := strings.TrimPrefix(r.URL.Path, "/Users/")
		delete(m.users, id)
		for i, v := range m.order {
			if v == id {
				m.order = append(m.order[:i], m.order[i+1:]...)
				break
			}
		}
		w.WriteHeader(204)
	default:
		scimError(w, 404)
	}
}

func (m *cursorMock) serveSPC(w http.ResponseWriter) {
	spc := map[string]any{
		"schemas":        []string{urnServiceProviderConfig},
		"patch":          map[string]any{"supported": true},
		"filter":         map[string]any{"supported": true},
		"bulk":           map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"changePassword": map[string]any{"supported": false},
		"etag":           map[string]any{"supported": false},
	}
	switch {
	case m.malformed:
		spc["pagination"] = map[string]any{"cursor": "yes", "index": true}
	case m.advertiseCursor:
		spc["pagination"] = map[string]any{"cursor": true, "index": true, "maxPageSize": 250}
	}
	writeSCIM(w, 200, spc)
}

func (m *cursorMock) serveList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	count := len(m.order)
	if c := q.Get("count"); c != "" {
		n, err := strconv.Atoi(c)
		if err != nil {
			scimError(w, 400)
			return
		}
		if n < 0 {
			n = 0
		}
		count = n
	}
	offset := 0
	if cur := q.Get("cursor"); cur != "" {
		n, err := strconv.Atoi(cur)
		if err != nil || n < 0 || n > len(m.order) {
			// Invalid cursor per RFC 9865 §2.1.
			writeSCIM(w, 400, map[string]any{
				"schemas":  []string{urnError},
				"scimType": "invalidCursor",
				"status":   "400",
			})
			return
		}
		offset = n
	}

	end := offset + count
	if end > len(m.order) {
		end = len(m.order)
	}
	var resources []map[string]any
	if count > 0 {
		for _, id := range m.order[offset:end] {
			resources = append(resources, m.users[id])
		}
	}
	body := map[string]any{
		"schemas":      []string{urnListResponse},
		"totalResults": len(m.order),
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}
	if end < len(m.order) {
		body["nextCursor"] = strconv.Itoa(end)
	}
	if offset > 0 {
		body["previousCursor"] = strconv.Itoa(offset)
	}
	writeSCIM(w, 200, body)
}

func runCursor(t *testing.T, h http.Handler) []Result {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	runner := &Runner{Client: scim.NewClient(srv.URL, "", ""), UserNameSuffix: "ctest"}
	return runner.CursorPagination(context.Background())
}

func TestCursorPackPassesOnCursorServer(t *testing.T) {
	results := runCursor(t, newCursorMock(true))
	for _, want := range []string{
		"rfc9865-spc-pagination", "rfc9865-first-page", "rfc9865-no-prevcursor-first",
		"rfc9865-count-ceiling", "rfc9865-follow-cursor", "rfc9865-invalid-cursor", "rfc9865-count-zero",
	} {
		if res := byID(t, results, want); res.Status != Pass {
			t.Errorf("check %s: expected pass, got %s (%s)", want, res.Status, res.Detail)
		}
	}
}

func TestCursorPackSkipsWhenNotAdvertised(t *testing.T) {
	results := runCursor(t, newCursorMock(false))
	gate := byID(t, results, "rfc9865-spc-pagination")
	if gate.Status != Skip {
		t.Fatalf("gate: expected skip, got %s", gate.Status)
	}
	for _, r := range results {
		if r.Status != Skip {
			t.Errorf("check %s: expected skip when cursor not advertised, got %s", r.ID, r.Status)
		}
	}
}

func TestCursorGateFailsOnMalformedAdvertisement(t *testing.T) {
	m := newCursorMock(true)
	m.malformed = true
	results := runCursor(t, m)
	if gate := byID(t, results, "rfc9865-spc-pagination"); gate.Status != Fail {
		t.Fatalf("gate: expected fail on non-boolean cursor, got %s (%s)", gate.Status, gate.Detail)
	}
}

func TestCursorInvalidCursorDetected(t *testing.T) {
	// A server that advertises cursor but returns 200 for a garbage cursor
	// should fail the invalid-cursor check.
	m := &badCursorMock{cursorMock: newCursorMock(true)}
	results := runCursor(t, m)
	if res := byID(t, results, "rfc9865-invalid-cursor"); res.Status != Fail {
		t.Fatalf("expected invalid-cursor to fail against a lax server, got %s", res.Status)
	}
}

// badCursorMock accepts any cursor (returns 200), violating RFC 9865 §2.1.
type badCursorMock struct{ *cursorMock }

func (m *badCursorMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/Users" && r.URL.Query().Get("cursor") == "not-a-real-cursor" {
		writeSCIM(w, 200, map[string]any{
			"schemas": []string{urnListResponse}, "totalResults": 0, "Resources": []any{},
		})
		return
	}
	m.cursorMock.ServeHTTP(w, r)
}
