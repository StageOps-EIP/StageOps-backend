package equipment

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type repositoryMock struct {
	docs       []doc
	created    *doc
	updated    *doc
	deletedID  string
	deletedRev string
}

func (m *repositoryMock) List(context.Context) ([]doc, error) { return m.docs, nil }

func (m *repositoryMock) FindByID(_ context.Context, id string) (*doc, error) {
	for i := range m.docs {
		if m.docs[i].ID == id {
			copy := m.docs[i]
			return &copy, nil
		}
	}
	return nil, ErrNotFound
}

func (m *repositoryMock) Create(_ context.Context, item *doc) error {
	m.created = item
	return nil
}

func (m *repositoryMock) Update(_ context.Context, item *doc) error {
	m.updated = item
	return nil
}

func (m *repositoryMock) Delete(_ context.Context, id, rev string) error {
	m.deletedID, m.deletedRev = id, rev
	return nil
}

func TestServiceListFiltersProjectAndModule(t *testing.T) {
	repo := &repositoryMock{docs: []doc{
		{ID: "equipment::1", ProjectID: "project::1", Module: "lighting"},
		{ID: "equipment::2", ProjectID: "project::1", Module: "audio"},
		{ID: "equipment::3", ProjectID: "project::2", Module: "lighting"},
	}}

	items, err := NewService(repo, nil).List(context.Background(), "project::1", "lighting")

	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "equipment::1", items[0].ID)
}

func TestServiceGetRejectsEquipmentOutsideScope(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{ID: "equipment::1", Type: docType, ProjectID: "project::2", Module: "lighting"}}}

	_, err := NewService(repo, nil).Get(context.Background(), "project::1", "lighting", "equipment::1")

	assert.ErrorIs(t, err, ErrNotFound)
}

func TestServiceCreateLightingEquipment(t *testing.T) {
	repo := &repositoryMock{}
	universe, address := 1, 100

	item, err := NewService(repo, nil).Create(context.Background(), "project::1", "lighting", Input{
		Name: "Spot 1", Kind: "moving-head", DMXUniverse: &universe, DMXAddress: &address, DMXChannels: 16,
	}, "user::1", "lumiere")

	require.NoError(t, err)
	require.NotNil(t, repo.created)
	assert.Equal(t, "project::1", item.ProjectID)
	assert.Equal(t, "lighting", item.Module)
	assert.Equal(t, "ok", item.Status)
	assert.Equal(t, 16, item.DMXChannels)
	assert.False(t, item.CreatedAt.IsZero())
}

func TestServiceCreateRejectsDMXOverlap(t *testing.T) {
	universe, existingAddress, newAddress := 1, 100, 110
	repo := &repositoryMock{docs: []doc{{
		ID: "equipment::1", ProjectID: "project::1", Module: "lighting", Name: "Spot 1",
		DMXUniverse: &universe, DMXAddress: &existingAddress, DMXChannels: 16,
	}}}

	_, err := NewService(repo, nil).Create(context.Background(), "project::1", "lighting", Input{
		Name: "Spot 2", Kind: "fixed", DMXUniverse: &universe, DMXAddress: &newAddress, DMXChannels: 8,
	}, "user::1", "lumiere")

	assert.ErrorIs(t, err, ErrDMXConflict)
}

func TestServiceUpdateExcludesCurrentEquipmentFromConflicts(t *testing.T) {
	universe, address := 1, 100
	repo := &repositoryMock{docs: []doc{{
		ID: "equipment::1", Rev: "2-rev", Type: docType, ProjectID: "project::1", Module: "lighting",
		Name: "Spot 1", DMXUniverse: &universe, DMXAddress: &address, DMXChannels: 16,
	}}}

	item, err := NewService(repo, nil).Update(context.Background(), "project::1", "lighting", "equipment::1", Input{
		Name: "Spot 1", Kind: "fixed", DMXUniverse: &universe, DMXAddress: &address, DMXChannels: 16,
	}, "user::1", "lumiere")

	require.NoError(t, err)
	assert.Equal(t, "fixed", item.Kind)
	assert.Equal(t, "2-rev", repo.updated.Rev)
}

func TestServiceDeleteUsesCurrentRevision(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "equipment::1", Rev: "2-rev", Type: docType, ProjectID: "project::1", Module: "audio",
	}}}

	err := NewService(repo, nil).Delete(context.Background(), "project::1", "audio", "equipment::1", "user::1", "son")

	require.NoError(t, err)
	assert.Equal(t, "equipment::1", repo.deletedID)
	assert.Equal(t, "2-rev", repo.deletedRev)
}

func TestValidateInputRejectsDMXOutsideLighting(t *testing.T) {
	universe, address := 1, 1
	err := validateInput("project::1", "audio", &Input{
		Name: "Console", Kind: "console", DMXUniverse: &universe, DMXAddress: &address,
	})

	var validationError *ValidationError
	assert.ErrorAs(t, err, &validationError)
}
