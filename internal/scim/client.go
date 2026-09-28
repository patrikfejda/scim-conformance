// Package scim provides a minimal SCIM 2.0 HTTP client used by the
// conformance checks. It deliberately does not model SCIM resources as
// typed structs: checks assert on raw responses, because the whole point
// is to observe what servers actually return.
package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MediaType is the SCIM media type per RFC 7644 section 3.1.
const MediaType = "application/scim+json"

// maxBodySize bounds how much of a response body is read (1 MiB is far
// beyond any sane single-resource response).
const maxBodySize = 1 << 20

// Client talks to one SCIM service provider.
type Client struct {
	baseURL    string
	token      string
	basicAuth  string // "user:pass"; used only when token is empty
	httpClient *http.Client
}

// NewClient builds a client for baseURL (e.g. "https://idp.example/scim/v2").
func NewClient(baseURL, token, basicAuth string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		basicAuth:  basicAuth,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// Response captures what checks assert on.
type Response struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

// JSON decodes the body into a generic map. Callers decide whether a
// decode failure is itself a conformance finding.
func (r *Response) JSON() (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal(r.Body, &out); err != nil {
		return nil, fmt.Errorf("response body is not a JSON object: %w", err)
	}
	return out, nil
}

// Do sends a JSON-encoded payload (may be nil) and returns the response.
func (c *Client) Do(ctx context.Context, method, path string, payload any) (*Response, error) {
	var raw []byte
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal request payload: %w", err)
		}
	}
	return c.DoRaw(ctx, method, path, raw, MediaType)
}

// DoRaw sends an arbitrary body, letting checks probe malformed-input
// handling. A nil body sends no payload.
func (c *Client) DoRaw(ctx context.Context, method, path string, body []byte, contentType string) (*Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", method, path, err)
	}
	req.Header.Set("Accept", MediaType)
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	switch {
	case c.token != "":
		req.Header.Set("Authorization", "Bearer "+c.token)
	case c.basicAuth != "":
		user, pass, ok := strings.Cut(c.basicAuth, ":")
		if !ok {
			return nil, fmt.Errorf("basic auth must be in user:pass form")
		}
		req.SetBasicAuth(user, pass)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("read response of %s %s: %w", method, path, err)
	}
	return &Response{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        data,
	}, nil
}
