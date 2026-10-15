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

// DeviceRepository persists offline-capable device registrations.
type DeviceRepository interface {
	Create(ctx context.Context, device *Device) error
	FindByID(ctx context.Context, id string) (*Device, error)
	ListByUser(ctx context.Context, userID string) ([]Device, error)
	Update(ctx context.Context, device *Device) error
}

// CouchDBDeviceRepository stores device documents in the authentication DB.
type CouchDBDeviceRepository struct {
	cfg    CouchConfig
	client *http.Client
}

func NewCouchDBDeviceRepository(cfg CouchConfig) *CouchDBDeviceRepository {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &CouchDBDeviceRepository{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}}
}

func (r *CouchDBDeviceRepository) documentURL(id string) string {
	return fmt.Sprintf("%s/%s/%s", r.cfg.BaseURL, url.PathEscape(r.cfg.DB), url.PathEscape(id))
}

func (r *CouchDBDeviceRepository) write(ctx context.Context, device *Device) error {
	body, err := json.Marshal(device)
	if err != nil {
		return fmt.Errorf("encoding device: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, r.documentURL(device.ID), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building device request: %w", err)
	}
	req.SetBasicAuth(r.cfg.Username, r.cfg.Password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("writing device: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CouchDB returned status %d while writing device", resp.StatusCode)
	}
	return nil
}

func (r *CouchDBDeviceRepository) Create(ctx context.Context, device *Device) error {
	return r.write(ctx, device)
}

func (r *CouchDBDeviceRepository) Update(ctx context.Context, device *Device) error {
	return r.write(ctx, device)
}

func (r *CouchDBDeviceRepository) FindByID(ctx context.Context, id string) (*Device, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.documentURL(id), nil)
	if err != nil {
		return nil, fmt.Errorf("building device request: %w", err)
	}
	req.SetBasicAuth(r.cfg.Username, r.cfg.Password)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reading device: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrDeviceNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CouchDB returned status %d while reading device", resp.StatusCode)
	}
	var device Device
	if err := json.NewDecoder(resp.Body).Decode(&device); err != nil {
		return nil, fmt.Errorf("decoding device: %w", err)
	}
	if device.Type != "device" {
		return nil, ErrDeviceNotFound
	}
	return &device, nil
}

func (r *CouchDBDeviceRepository) ListByUser(ctx context.Context, userID string) ([]Device, error) {
	params := url.Values{}
	params.Set("key", fmt.Sprintf("%q", userID))
	params.Set("include_docs", "true")
	rawURL := fmt.Sprintf("%s/%s/_design/devices/_view/by_user?%s", r.cfg.BaseURL, url.PathEscape(r.cfg.DB), params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building device list request: %w", err)
	}
	req.SetBasicAuth(r.cfg.Username, r.cfg.Password)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing devices: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CouchDB returned status %d while listing devices", resp.StatusCode)
	}
	var result struct {
		Rows []struct {
			Doc Device `json:"doc"`
		} `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding devices: %w", err)
	}
	devices := make([]Device, 0, len(result.Rows))
	for _, row := range result.Rows {
		if row.Doc.Type == "device" {
			devices = append(devices, row.Doc)
		}
	}
	return devices, nil
}
