package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Repository is the persistence contract for audit log entries.
// It is write-only: no reads, no deletes.
type Repository interface {
	Log(ctx context.Context, entry AuditEntry) error
}

// CouchConfig holds CouchDB connection settings for the audit repository.
type CouchConfig struct {
	BaseURL  string
	DB       string
	Username string
	Password string
}

// CouchDBRepository implements Repository via the CouchDB HTTP API.
type CouchDBRepository struct {
	cfg    CouchConfig
	client *http.Client
}

// NewCouchDBRepository creates a ready-to-use CouchDB audit repository.
func NewCouchDBRepository(cfg CouchConfig) *CouchDBRepository {
	return &CouchDBRepository{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Log writes an audit entry to CouchDB using PUT /<db>/<id>.
func (r *CouchDBRepository) Log(ctx context.Context, entry AuditEntry) error {
	body, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encoding audit entry: %w", err)
	}

	rawURL := fmt.Sprintf("%s/%s/%s", r.cfg.BaseURL, r.cfg.DB, entry.ID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rawURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(r.cfg.Username, r.cfg.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("CouchDB returned status %d for audit log", resp.StatusCode)
	}

	return nil
}
