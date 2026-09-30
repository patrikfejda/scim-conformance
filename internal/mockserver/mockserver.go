// Package mockserver implements a minimal, compliant SCIM 2.0 service
// provider that a provisioning *client* (Keycloak's keycloak-scim, Entra,
// Okta, authentik's provider) can be pointed at. Every inbound request is
// validated against RFC 7643/7644 client-side expectations and recorded,
// so the tool grades the provisioner's behaviour — the inverse of the
// black-box server runner, and something no existing SCIM tool does.
package mockserver

import (
	"net/http"
	"strings"
	"sync"

	"github.com/patrikfejda/scim-conformance/internal/scim"
)

const (
	urnUser      = "urn:ietf:params:scim:schemas:core:2.0:User"
	urnGroup     = "urn:ietf:params:scim:schemas:core:2.0:Group"
	urnPatchOp   = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	urnListResp  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	urnSPConfig  = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	urnErrorResp = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// Observation is one thing noticed about the client's behaviour.
type Observation struct {
	Check    string `json:"check"`
	Severity string `json:"severity"` // required | advisory | info
	OK       bool   `json:"ok"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Detail   string `json:"detail,omitempty"`
}

// Server is a stateful mock SCIM provider recording client behaviour.
type Server struct {
	mu           sync.Mutex
	users        map[string]map[string]any
	groups       map[string]map[string]any
	nextID       int
	observations []Observation
	sawDiscovery bool
	seenChecks   map[string]bool // dedupe repeated per-request checks
}

// New builds an empty mock server.
func New() *Server {
	return &Server{
		users:      map[string]map[string]any{},
		groups:     map[string]map[string]any{},
		seenChecks: map[string]bool{},
	}
}

// Observations returns a copy of everything recorded so far, plus derived
// end-of-session observations (e.g. whether discovery ever happened).
func (s *Server) Observations() []Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Observation, len(s.observations))
	copy(out, s.observations)
	out = append(out, Observation{
		Check:    "client-reads-serviceproviderconfig",
		Severity: "advisory",
		OK:       s.sawDiscovery,
		Detail:   "a well-behaved client discovers server capabilities before provisioning",
	})
	return out
}

// record appends an observation, de-duplicating repeated identical checks
// so a client that sends 500 users doesn't produce 500 identical lines.
func (s *Server) record(o Observation) {
	key := o.Check + "|" + o.Method + "|" + boolKey(o.OK) + "|" + o.Detail
	if s.seenChecks[key] {
		return
	}
	s.seenChecks[key] = true
	s.observations = append(s.observations, o)
}

func boolKey(b bool) string {
	if b {
		return "ok"
	}
	return "fail"
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/ServiceProviderConfig":
		s.sawDiscovery = true
		writeSCIM(w, http.StatusOK, serviceProviderConfig())
	case r.Method == http.MethodGet && (r.URL.Path == "/Schemas" || r.URL.Path == "/ResourceTypes"):
		s.sawDiscovery = true
		writeSCIM(w, http.StatusOK, emptyList())
	case r.Method == http.MethodPost && r.URL.Path == "/Users":
		s.handleCreate(w, r, "User", urnUser, s.users)
	case r.Method == http.MethodPost && r.URL.Path == "/Groups":
		s.handleCreate(w, r, "Group", urnGroup, s.groups)
	case r.URL.Path == "/Users" || r.URL.Path == "/Groups":
		writeSCIM(w, http.StatusOK, emptyList()) // GET list (filter lookups)
	case strings.HasPrefix(r.URL.Path, "/Users/"):
		s.handleByID(w, r, s.users, strings.TrimPrefix(r.URL.Path, "/Users/"))
	case strings.HasPrefix(r.URL.Path, "/Groups/"):
		s.handleByID(w, r, s.groups, strings.TrimPrefix(r.URL.Path, "/Groups/"))
	default:
		writeError(w, http.StatusNotFound)
	}
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request, kind, urn string, store map[string]map[string]any) {
	body := s.checkWriteRequest(r, urn)
	if body == nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	s.nextID++
	id := kind + "-" + itoa(s.nextID)
	body["id"] = id
	store[id] = body
	writeSCIM(w, http.StatusCreated, body)
}

func (s *Server) handleByID(w http.ResponseWriter, r *http.Request, store map[string]map[string]any, id string) {
	resource, ok := store[id]
	switch r.Method {
	case http.MethodGet:
		if !ok {
			writeError(w, http.StatusNotFound)
			return
		}
		writeSCIM(w, http.StatusOK, resource)
	case http.MethodPut:
		body := s.checkWriteRequest(r, resourceURN(store))
		if body == nil || !ok {
			writeError(w, http.StatusBadRequest)
			return
		}
		body["id"] = id
		store[id] = body
		writeSCIM(w, http.StatusOK, body)
	case http.MethodPatch:
		if s.checkPatchRequest(r) && ok {
			writeSCIM(w, http.StatusOK, resource)
			return
		}
		writeError(w, http.StatusBadRequest)
	case http.MethodDelete:
		delete(store, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusBadRequest)
	}
}

// checkWriteRequest validates a POST/PUT body and Content-Type, records
// observations, and returns the parsed body (nil if unparseable).
func (s *Server) checkWriteRequest(r *http.Request, expectedURN string) map[string]any {
	s.checkContentType(r)
	body, err := decodeBody(r)
	if err != nil {
		s.record(Observation{Check: "client-sends-valid-json", Severity: "required", OK: false,
			Method: r.Method, Path: r.URL.Path, Detail: err.Error()})
		return nil
	}
	s.record(Observation{Check: "client-sends-valid-json", Severity: "required", OK: true, Method: r.Method, Path: r.URL.Path})

	if hasSchema(body, expectedURN) {
		s.record(Observation{Check: "client-declares-resource-schema", Severity: "required", OK: true, Method: r.Method, Path: r.URL.Path})
	} else {
		s.record(Observation{Check: "client-declares-resource-schema", Severity: "required", OK: false,
			Method: r.Method, Path: r.URL.Path, Detail: "request body schemas does not include " + expectedURN})
	}
	if _, present := body["id"]; present && r.Method == http.MethodPost {
		s.record(Observation{Check: "client-omits-id-on-create", Severity: "advisory", OK: false,
			Method: r.Method, Path: r.URL.Path, Detail: "client sent a server-assigned id on create (RFC 7643 §3.1: id is server-managed)"})
	}
	return body
}

func (s *Server) checkPatchRequest(r *http.Request) bool {
	s.checkContentType(r)
	body, err := decodeBody(r)
	if err != nil {
		s.record(Observation{Check: "client-sends-valid-json", Severity: "required", OK: false, Method: r.Method, Path: r.URL.Path, Detail: err.Error()})
		return false
	}
	ok := true
	if !hasSchema(body, urnPatchOp) {
		s.record(Observation{Check: "client-patch-declares-patchop", Severity: "required", OK: false,
			Method: r.Method, Path: r.URL.Path, Detail: "PATCH body schemas must include " + urnPatchOp})
		ok = false
	} else {
		s.record(Observation{Check: "client-patch-declares-patchop", Severity: "required", OK: true, Method: r.Method, Path: r.URL.Path})
	}
	ops, hasOps := body["Operations"].([]any)
	if !hasOps || len(ops) == 0 {
		s.record(Observation{Check: "client-patch-has-operations", Severity: "required", OK: false,
			Method: r.Method, Path: r.URL.Path, Detail: "PATCH body must contain a non-empty Operations array"})
		return false
	}
	s.record(Observation{Check: "client-patch-has-operations", Severity: "required", OK: true, Method: r.Method, Path: r.URL.Path})
	for _, raw := range ops {
		op, _ := raw.(map[string]any)
		verb, _ := op["op"].(string)
		switch strings.ToLower(verb) {
		case "add", "remove", "replace":
		default:
			s.record(Observation{Check: "client-patch-valid-op", Severity: "required", OK: false,
				Method: r.Method, Path: r.URL.Path, Detail: "invalid PATCH op verb: " + verb + " (RFC 7644 §3.5.2 allows add/remove/replace)"})
			ok = false
		}
	}
	if ok {
		s.record(Observation{Check: "client-patch-valid-op", Severity: "required", OK: true, Method: r.Method, Path: r.URL.Path})
	}
	return ok
}

func (s *Server) checkContentType(r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, scim.MediaType) {
		s.record(Observation{Check: "client-sends-scim-content-type", Severity: "advisory", OK: true, Method: r.Method, Path: r.URL.Path})
		return
	}
	s.record(Observation{Check: "client-sends-scim-content-type", Severity: "advisory", OK: false,
		Method: r.Method, Path: r.URL.Path, Detail: "Content-Type is " + ct + ", expected application/scim+json (RFC 7644 §3.1)"})
}
