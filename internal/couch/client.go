// Package couch provides a thin HTTP client over the CouchDB API.
// All domain repositories embed *Client to share the connection settings and
// the http.Client instance.
package couch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("document not found")
	ErrConflict = errors.New("document conflict")
)

// Config holds connection settings for a CouchDB instance.
type Config struct {
	BaseURL  string
	DB       string
	Username string
	Password string
}

// Client wraps an http.Client with CouchDB connection settings.
type Client struct {
	cfg  Config
	http *http.Client
}

// New returns a Client ready to use.
func New(cfg Config) *Client {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// Ping verifies that CouchDB is reachable and ready to serve requests.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/_up", nil)
	if err != nil {
		return fmt.Errorf("building health request: %w", err)
	}
	req.SetBasicAuth(c.cfg.Username, c.cfg.Password)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("checking CouchDB health: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CouchDB health returned status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) documentURL(id string) string {
	return fmt.Sprintf("%s/%s/%s", c.cfg.BaseURL, url.PathEscape(c.cfg.DB), url.PathEscape(id))
}

// GetDoc fetches the document with the given CouchDB _id and unmarshals it
// into dest (must be a non-nil pointer). Returns ErrNotFound on 404.
func (c *Client) GetDoc(ctx context.Context, id string, dest interface{}) error {
	rawURL := c.documentURL(id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(c.cfg.Username, c.cfg.Password)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("querying CouchDB: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CouchDB returned status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return fmt.Errorf("decoding document: %w", err)
	}
	return nil
}

// PutDoc creates or updates the document identified by id.
// On update, doc must carry the current _rev value or CouchDB returns a conflict.
func (c *Client) PutDoc(ctx context.Context, id string, doc interface{}) error {
	body, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encoding document: %w", err)
	}

	rawURL := c.documentURL(id)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rawURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("writing to CouchDB: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return ErrConflict
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CouchDB returned status %d", resp.StatusCode)
	}
	return nil
}

// DeleteDoc deletes the document identified by id at the given revision.
func (c *Client) DeleteDoc(ctx context.Context, id, rev string) error {
	parsed, err := url.Parse(c.documentURL(id))
	if err != nil {
		return fmt.Errorf("building document URL: %w", err)
	}
	query := parsed.Query()
	query.Set("rev", rev)
	parsed.RawQuery = query.Encode()
	rawURL := parsed.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, rawURL, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(c.cfg.Username, c.cfg.Password)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("deleting from CouchDB: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode == http.StatusConflict {
		return ErrConflict
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("CouchDB returned status %d", resp.StatusCode)
	}
	return nil
}

// ListByView queries _design/{design}/_view/{view}?include_docs=true and
// unmarshals the doc field of every row into dest (must be a pointer to a slice).
func (c *Client) ListByView(ctx context.Context, design, view string, dest interface{}) error {
	rawURL := fmt.Sprintf(
		"%s/%s/_design/%s/_view/%s?include_docs=true",
		c.cfg.BaseURL,
		url.PathEscape(c.cfg.DB),
		url.PathEscape(design),
		url.PathEscape(view),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(c.cfg.Username, c.cfg.Password)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("querying view: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CouchDB returned status %d", resp.StatusCode)
	}

	var rawResp struct {
		Rows []struct {
			Doc json.RawMessage `json:"doc"`
		} `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rawResp); err != nil {
		return fmt.Errorf("decoding view response: %w", err)
	}

	docs := make([]json.RawMessage, len(rawResp.Rows))
	for i, row := range rawResp.Rows {
		docs[i] = row.Doc
	}

	arr, err := json.Marshal(docs)
	if err != nil {
		return fmt.Errorf("marshaling docs: %w", err)
	}
	return json.Unmarshal(arr, dest)
}
