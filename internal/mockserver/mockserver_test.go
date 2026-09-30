package mockserver

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/patrikfejda/scim-conformance/internal/scim"
)

func find(t *testing.T, obs []Observation, check string) Observation {
	t.Helper()
	for _, o := range obs {
		if o.Check == check {
			return o
		}
	}
	t.Fatalf("no observation for check %q", check)
	return Observation{}
}

// wellBehavedClient exercises the mock server the way a compliant
// provisioner would: discovery, then a correct user create and PATCH.
func TestWellBehavedClientProducesCleanObservations(t *testing.T) {
	s := New()
	srv := httptest.NewServer(s)
	defer srv.Close()

	do := func(method, path, body string) {
		var r *http.Request
		if body != "" {
			r, _ = http.NewRequest(method, srv.URL+path, bytes.NewBufferString(body))
			r.Header.Set("Content-Type", scim.MediaType)
		} else {
			r, _ = http.NewRequest(method, srv.URL+path, nil)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	do(http.MethodGet, "/ServiceProviderConfig", "")
	do(http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice"}`)
	do(http.MethodPatch, "/Users/User-1", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Alice"}]}`)

	obs := s.Observations()
	for _, check := range []string{
		"client-reads-serviceproviderconfig",
		"client-sends-scim-content-type",
		"client-declares-resource-schema",
		"client-patch-declares-patchop",
		"client-patch-valid-op",
	} {
		if o := find(t, obs, check); !o.OK {
			t.Errorf("check %q: expected OK, got fail (%s)", check, o.Detail)
		}
	}
}

// misbehavingClient triggers each failure path: wrong content type, missing
// schema, id-on-create, bad PATCH op, no discovery.
func TestMisbehavingClientIsFlagged(t *testing.T) {
	s := New()
	srv := httptest.NewServer(s)
	defer srv.Close()

	// POST with wrong content type, missing schemas, and an id present.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/Users", bytes.NewBufferString(`{"userName":"bob","id":"client-chosen"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// PATCH with an invalid op verb.
	req, _ = http.NewRequest(http.MethodPatch, srv.URL+"/Users/User-1", bytes.NewBufferString(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"upsert","path":"x","value":"y"}]}`))
	req.Header.Set("Content-Type", scim.MediaType)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	obs := s.Observations()
	for _, check := range []string{
		"client-sends-scim-content-type",
		"client-declares-resource-schema",
		"client-omits-id-on-create",
		"client-patch-valid-op",
		"client-reads-serviceproviderconfig",
	} {
		if o := find(t, obs, check); o.OK {
			t.Errorf("check %q: expected failure to be flagged, got OK", check)
		}
	}
}

func TestObservationsDeduplicated(t *testing.T) {
	s := New()
	srv := httptest.NewServer(s)
	defer srv.Close()

	// Two identical good creates must not double the observation list.
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/Users", bytes.NewBufferString(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"x"}`))
		req.Header.Set("Content-Type", scim.MediaType)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
	}
	count := 0
	for _, o := range s.Observations() {
		if o.Check == "client-declares-resource-schema" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected schema check deduplicated to 1, got %d", count)
	}
}
