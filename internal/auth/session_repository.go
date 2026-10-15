package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SessionRepository persists refresh-token families and their revocation state.
type SessionRepository interface {
	Create(ctx context.Context, session *Session) error
	FindByID(ctx context.Context, id string) (*Session, error)
	FindByRefreshHash(ctx context.Context, hash string) (*Session, error)
	Update(ctx context.Context, session *Session) error
	RevokeAllByUser(ctx context.Context, userID string, revokedAt time.Time) error
}

// CouchDBSessionRepository stores session documents in the authentication DB.
type CouchDBSessionRepository struct {
	cfg    CouchConfig
	client *http.Client
}

// NewCouchDBSessionRepository creates a CouchDB-backed session repository.
func NewCouchDBSessionRepository(cfg CouchConfig) *CouchDBSessionRepository {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &CouchDBSessionRepository{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}}
}

func (r *CouchDBSessionRepository) sessionURL(id string) string {
	return fmt.Sprintf("%s/%s/%s", r.cfg.BaseURL, url.PathEscape(r.cfg.DB), url.PathEscape(id))
}

func (r *CouchDBSessionRepository) do(ctx context.Context, method, rawURL string, body []byte) (*http.Response, error) {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, fmt.Errorf("building session request: %w", err)
	}
	req.SetBasicAuth(r.cfg.Username, r.cfg.Password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying CouchDB sessions: %w", err)
	}
	return resp, nil
}

// Create stores a new session document.
func (r *CouchDBSessionRepository) Create(ctx context.Context, session *Session) error {
	body, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encoding session: %w", err)
	}
	resp, err := r.do(ctx, http.MethodPut, r.sessionURL(session.ID), body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("CouchDB returned status %d while creating session", resp.StatusCode)
	}
	return nil
}

// FindByID fetches one session document.
func (r *CouchDBSessionRepository) FindByID(ctx context.Context, id string) (*Session, error) {
	resp, err := r.do(ctx, http.MethodGet, r.sessionURL(id), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrSessionNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CouchDB returned status %d while reading session", resp.StatusCode)
	}
	return decodeSession(resp)
}

// FindByRefreshHash finds the current or immediately previous token fingerprint.
func (r *CouchDBSessionRepository) FindByRefreshHash(ctx context.Context, hash string) (*Session, error) {
	params := url.Values{}
	params.Set("key", fmt.Sprintf("%q", hash))
	params.Set("include_docs", "true")
	params.Set("limit", "1")
	rawURL := fmt.Sprintf("%s/%s/_design/sessions/_view/by_refresh_hash?%s", r.cfg.BaseURL, url.PathEscape(r.cfg.DB), params.Encode())
	resp, err := r.do(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CouchDB returned status %d while finding session", resp.StatusCode)
	}
	var result struct {
		Rows []struct {
			Doc Session `json:"doc"`
		} `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding session view: %w", err)
	}
	if len(result.Rows) == 0 || result.Rows[0].Doc.Type != "session" {
		return nil, ErrSessionNotFound
	}
	return &result.Rows[0].Doc, nil
}

// Update replaces an existing session using its CouchDB revision.
func (r *CouchDBSessionRepository) Update(ctx context.Context, session *Session) error {
	body, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encoding session: %w", err)
	}
	resp, err := r.do(ctx, http.MethodPut, r.sessionURL(session.ID), body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("updating session: %w", ErrInvalidRefresh)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CouchDB returned status %d while updating session", resp.StatusCode)
	}
	return nil
}

// RevokeAllByUser revokes every active refresh-token family for a user.
func (r *CouchDBSessionRepository) RevokeAllByUser(ctx context.Context, userID string, revokedAt time.Time) error {
	params := url.Values{}
	params.Set("key", fmt.Sprintf("%q", userID))
	params.Set("include_docs", "true")
	rawURL := fmt.Sprintf("%s/%s/_design/sessions/_view/by_user?%s", r.cfg.BaseURL, url.PathEscape(r.cfg.DB), params.Encode())
	resp, err := r.do(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CouchDB returned status %d while listing sessions", resp.StatusCode)
	}
	var result struct {
		Rows []struct {
			Doc Session `json:"doc"`
		} `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding user sessions: %w", err)
	}
	for i := range result.Rows {
		session := &result.Rows[i].Doc
		if session.Type != "session" || session.RevokedAt != nil {
			continue
		}
		session.RevokedAt = &revokedAt
		if err := r.Update(ctx, session); err != nil {
			return fmt.Errorf("revoking session %s: %w", session.ID, err)
		}
	}
	return nil
}

func decodeSession(resp *http.Response) (*Session, error) {
	var session Session
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return nil, fmt.Errorf("decoding session: %w", err)
	}
	if session.Type != "session" {
		return nil, ErrSessionNotFound
	}
	return &session, nil
}
