package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var ErrModuleNotFound = errors.New("module not found")

// CouchConfig holds CouchDB connection settings for the modules repository.
type CouchConfig struct {
	BaseURL  string
	DB       string
	Username string
	Password string
}

// Repository defines the persistence contract for modules.
type Repository interface {
	GetByName(ctx context.Context, name string) (*Module, error)
	Toggle(ctx context.Context, name string) (*Module, error)
	GetAll(ctx context.Context) ([]Module, error)
}

// CouchDBRepository implements Repository via the CouchDB HTTP API.
type CouchDBRepository struct {
	cfg    CouchConfig
	client *http.Client
}

// NewCouchDBRepository creates a ready-to-use CouchDB modules repository.
func NewCouchDBRepository(cfg CouchConfig) *CouchDBRepository {
	return &CouchDBRepository{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// GetByName fetches a module document by its CouchDB _id ("module::<name>").
func (r *CouchDBRepository) GetByName(ctx context.Context, name string) (*Module, error) {
	docID := fmt.Sprintf("module::%s", name)
	rawURL := fmt.Sprintf("%s/%s/%s", r.cfg.BaseURL, r.cfg.DB, docID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(r.cfg.Username, r.cfg.Password)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying CouchDB: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrModuleNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CouchDB returned status %d", resp.StatusCode)
	}

	var mod Module
	if err := json.NewDecoder(resp.Body).Decode(&mod); err != nil {
		return nil, fmt.Errorf("decoding module document: %w", err)
	}

	return &mod, nil
}

// Toggle flips the active state of a module and writes it back to CouchDB.
func (r *CouchDBRepository) Toggle(ctx context.Context, name string) (*Module, error) {
	mod, err := r.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}

	mod.Active = !mod.Active
	mod.UpdatedAt = time.Now().UTC()

	body, err := json.Marshal(mod)
	if err != nil {
		return nil, fmt.Errorf("encoding module document: %w", err)
	}

	rawURL := fmt.Sprintf("%s/%s/%s", r.cfg.BaseURL, r.cfg.DB, mod.ID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(r.cfg.Username, r.cfg.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("updating module document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("document conflict on module toggle")
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CouchDB returned status %d", resp.StatusCode)
	}

	return mod, nil
}

// couchAllDocsResponse models the CouchDB _all_docs response envelope.
type couchAllDocsResponse struct {
	Rows []struct {
		Doc Module `json:"doc"`
	} `json:"rows"`
}

// GetAll returns all module documents using _all_docs with startkey/endkey.
func (r *CouchDBRepository) GetAll(ctx context.Context) ([]Module, error) {
	rawURL := fmt.Sprintf(
		`%s/%s/_all_docs?include_docs=true&startkey="module::"&endkey="module::\ufff0"`,
		r.cfg.BaseURL, r.cfg.DB,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(r.cfg.Username, r.cfg.Password)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying CouchDB: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CouchDB returned status %d", resp.StatusCode)
	}

	var allDocs couchAllDocsResponse
	if err := json.NewDecoder(resp.Body).Decode(&allDocs); err != nil {
		return nil, fmt.Errorf("decoding _all_docs response: %w", err)
	}

	mods := make([]Module, 0, len(allDocs.Rows))
	for _, row := range allDocs.Rows {
		mods = append(mods, row.Doc)
	}

	return mods, nil
}
