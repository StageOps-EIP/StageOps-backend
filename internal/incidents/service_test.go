package incidents

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

func (m *repositoryMock) Create(_ context.Context, incident *doc) error {
	m.created = incident
	return nil
}

func (m *repositoryMock) Update(_ context.Context, incident *doc) error {
	m.updated = incident
	return nil
}

func (m *repositoryMock) Delete(_ context.Context, id, rev string) error {
	m.deletedID, m.deletedRev = id, rev
	return nil
}

func TestServiceListFiltersProjectAndModule(t *testing.T) {
	repo := &repositoryMock{docs: []doc{
		{ID: "incident::1", ProjectID: "project::1", Module: "lighting"},
		{ID: "incident::2", ProjectID: "project::1", Module: "audio"},
	}}

	result, err := NewService(repo, nil).List(context.Background(), "project::1", "lighting")

	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "incident::1", result[0].ID)
}

func TestServiceGetRejectsIncidentOutsideScope(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Type: docType, ProjectID: "project::2", Module: "lighting",
	}}}

	_, err := NewService(repo, nil).Get(context.Background(), "project::1", "lighting", "incident::1")

	assert.ErrorIs(t, err, ErrNotFound)
}

func TestServiceCreateUsesAuthenticatedReporter(t *testing.T) {
	repo := &repositoryMock{}
	input := Input{Title: "Panne", Description: "Le projecteur ne répond plus", Severity: "high"}

	result, err := NewService(repo, nil).Create(context.Background(), "project::1", "lighting", input, "user::1", "lumiere")

	require.NoError(t, err)
	assert.Equal(t, "user::1", result.ReportedBy)
	assert.Equal(t, "open", result.Status)
	assert.NotNil(t, result.Images)
	assert.False(t, result.CreatedAt.IsZero())
}

func TestServiceCreateValidatesDescription(t *testing.T) {
	repo := &repositoryMock{}

	_, err := NewService(repo, nil).Create(context.Background(), "project::1", "audio", Input{
		Title: "Panne", Severity: "medium",
	}, "user::1", "son")

	var validationError *ValidationError
	assert.ErrorAs(t, err, &validationError)
}

func TestServiceUpdateSetsResolutionDate(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Rev: "2-rev", Type: docType, ProjectID: "project::1", Module: "audio",
		Title: "Panne", Description: "Console", Severity: "high", Status: "open",
	}}}

	result, err := NewService(repo, nil).Update(context.Background(), "project::1", "audio", "incident::1", Input{
		Title: "Panne", Description: "Console réparée", Severity: "high", Status: "resolved",
	}, "user::1", "son")

	require.NoError(t, err)
	assert.NotNil(t, result.ResolvedAt)
	assert.Equal(t, "2-rev", repo.updated.Rev)
}

func TestServiceDeleteUsesCurrentRevision(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Rev: "2-rev", Type: docType, ProjectID: "project::1", Module: "lighting",
	}}}

	err := NewService(repo, nil).Delete(context.Background(), "project::1", "lighting", "incident::1", "user::1", "lumiere")

	require.NoError(t, err)
	assert.Equal(t, "incident::1", repo.deletedID)
	assert.Equal(t, "2-rev", repo.deletedRev)
}
