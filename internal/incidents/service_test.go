package incidents

import (
	"context"
	"testing"
	"time"

	"github.com/stageops/backend/internal/tenant"
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

// The mock keeps its documents up to date so that reads made after a write see it.
func (m *repositoryMock) Create(_ context.Context, incident *doc) error {
	m.created = incident
	m.docs = append(m.docs, *incident)
	return nil
}

func (m *repositoryMock) Update(_ context.Context, incident *doc) error {
	m.updated = incident
	for i := range m.docs {
		if m.docs[i].ID == incident.ID {
			m.docs[i] = *incident
		}
	}
	return nil
}

func (m *repositoryMock) Delete(_ context.Context, id, rev string) error {
	m.deletedID, m.deletedRev = id, rev
	remaining := make([]doc, 0, len(m.docs))
	for _, existing := range m.docs {
		if existing.ID != id {
			remaining = append(remaining, existing)
		}
	}
	m.docs = remaining
	return nil
}

func TestServiceListFiltersProjectAndModule(t *testing.T) {
	repo := &repositoryMock{docs: []doc{
		{ID: "incident::1", ProjectID: "project::1", Module: "lighting"},
		{ID: "incident::2", ProjectID: "project::1", Module: "audio"},
	}}

	result, err := NewService(repo, nil, nil, nil).List(context.Background(), "project::1", "lighting", ListFilter{})

	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "incident::1", result[0].ID)
}

func TestServiceGetRejectsIncidentOutsideScope(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Type: docType, ProjectID: "project::2", Module: "lighting",
	}}}

	_, err := NewService(repo, nil, nil, nil).Get(context.Background(), "project::1", "lighting", "incident::1")

	assert.ErrorIs(t, err, ErrNotFound)
}

func TestServiceCreateUsesAuthenticatedReporter(t *testing.T) {
	repo := &repositoryMock{}
	input := Input{Title: "Panne", Description: "Le projecteur ne répond plus", Severity: "high", Date: "2027-06-11"}

	result, err := NewService(repo, nil, nil, nil).Create(tenant.WithTheatreID(context.Background(), "theatre::one"), "project::1", "lighting", input, "user::1", "lumiere")

	require.NoError(t, err)
	assert.Equal(t, "user::1", result.ReportedBy)
	assert.Equal(t, "open", result.Status)
	assert.NotNil(t, result.Images)
	assert.False(t, result.CreatedAt.IsZero())
}

func TestServiceCreateValidatesDescription(t *testing.T) {
	repo := &repositoryMock{}

	_, err := NewService(repo, nil, nil, nil).Create(context.Background(), "project::1", "audio", Input{
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

	result, err := NewService(repo, nil, nil, nil).Update(context.Background(), "project::1", "audio", "incident::1", Input{
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

	err := NewService(repo, nil, nil, nil).Delete(context.Background(), "project::1", "lighting", "incident::1", "user::1", "lumiere")

	require.NoError(t, err)
	assert.Equal(t, "incident::1", repo.deletedID)
	assert.Equal(t, "2-rev", repo.deletedRev)
}

type calendarMock struct{ start, end string }

func (m calendarMock) DateRange(context.Context, string) (time.Time, time.Time, error) {
	start, _ := time.Parse(time.DateOnly, m.start)
	end, _ := time.Parse(time.DateOnly, m.end)
	return start, end, nil
}

var festival = calendarMock{start: "2027-06-10", end: "2027-06-14"}

type stateChange struct {
	equipmentID          string
	hadActive, hasActive bool
}

type equipmentMock struct {
	known   map[string]bool
	changes []stateChange
}

func (m *equipmentMock) Exists(_ context.Context, _, _, id string) (bool, error) {
	return m.known[id], nil
}

func (m *equipmentMock) ApplyIncidentState(_ context.Context, _, _, id string, hadActive, hasActive bool, _, _ string) error {
	m.changes = append(m.changes, stateChange{id, hadActive, hasActive})
	return nil
}

func scopedContext() context.Context {
	return tenant.WithTheatreID(context.Background(), "theatre::one")
}

func TestServiceCreateRequiresDate(t *testing.T) {
	repo := &repositoryMock{}

	_, err := NewService(repo, nil, festival, nil).Create(scopedContext(), "project::1", "lighting", Input{
		Title: "Lampe grillée", Description: "Découpe 3", Severity: "low",
	}, "user::1", "lumiere")

	var validationError *ValidationError
	require.ErrorAs(t, err, &validationError)
	assert.Contains(t, validationError.Message, "'date'")
	assert.Nil(t, repo.created)
}

func TestServiceCreateStoresDateAndTimestamps(t *testing.T) {
	repo := &repositoryMock{}

	result, err := NewService(repo, nil, festival, nil).Create(scopedContext(), "project::1", "lighting", Input{
		Title: "Lampe grillée", Description: "Découpe 3", Severity: "low", Date: "2027-06-12",
	}, "user::1", "lumiere")

	require.NoError(t, err)
	assert.Equal(t, "2027-06-12", result.Date)
	assert.Equal(t, "open", result.Status)
	assert.Nil(t, result.ResolvedAt)
	assert.WithinDuration(t, time.Now().UTC(), result.CreatedAt, time.Second)
}

func TestServiceCreateValidatesDate(t *testing.T) {
	cases := map[string]string{
		"malformed":          "11/06/2027",
		"before the project": "2027-06-09",
		"after the project":  "2027-06-15",
	}

	for name, date := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &repositoryMock{}

			_, err := NewService(repo, nil, festival, nil).Create(scopedContext(), "project::1", "audio", Input{
				Title: "Larsen", Description: "Retour scène", Severity: "medium", Date: date,
			}, "user::1", "son")

			var validationError *ValidationError
			assert.ErrorAs(t, err, &validationError)
			assert.Nil(t, repo.created)
		})
	}
}

func TestServiceCreateRejectsUnknownEquipment(t *testing.T) {
	repo := &repositoryMock{}
	linker := &equipmentMock{known: map[string]bool{}}

	_, err := NewService(repo, nil, festival, linker).Create(scopedContext(), "project::1", "audio", Input{
		Title: "HF muet", Description: "Pas de signal", Severity: "high", Date: "2027-06-11", EquipmentID: "equipment::ghost",
	}, "user::1", "son")

	var validationError *ValidationError
	assert.ErrorAs(t, err, &validationError)
	assert.Nil(t, repo.created)
	assert.Empty(t, linker.changes)
}

func TestServiceCreateFlagsLinkedEquipment(t *testing.T) {
	repo := &repositoryMock{}
	linker := &equipmentMock{known: map[string]bool{"equipment::hf1": true}}

	result, err := NewService(repo, nil, festival, linker).Create(scopedContext(), "project::1", "audio", Input{
		Title: "HF muet", Description: "Pas de signal", Severity: "high", Date: "2027-06-11", EquipmentID: "equipment::hf1",
	}, "user::1", "son")

	require.NoError(t, err)
	assert.Equal(t, "2027-06-11", result.Date)
	assert.Equal(t, []stateChange{{"equipment::hf1", false, true}}, linker.changes)
}

func TestServiceUpdateResolvingLastIncidentRestoresEquipment(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Rev: "1-rev", Type: docType, ProjectID: "project::1", Module: "audio",
		Title: "HF muet", Description: "Pas de signal", Severity: "high", Status: "open",
		EquipmentID: "equipment::hf1", Date: "2027-06-11",
	}}}
	linker := &equipmentMock{known: map[string]bool{"equipment::hf1": true}}

	result, err := NewService(repo, nil, festival, linker).Update(scopedContext(), "project::1", "audio", "incident::1", Input{
		Title: "HF muet", Description: "Pile changée", Severity: "high", Status: "resolved", EquipmentID: "equipment::hf1",
	}, "user::1", "son")

	require.NoError(t, err)
	assert.Equal(t, "2027-06-11", result.Date, "omitted date keeps the stored one")
	assert.NotNil(t, result.ResolvedAt)
	assert.Equal(t, []stateChange{{"equipment::hf1", true, false}}, linker.changes)
}

func TestServiceUpdateKeepsFlagWhileAnotherIncidentIsActive(t *testing.T) {
	repo := &repositoryMock{docs: []doc{
		{ID: "incident::1", Type: docType, ProjectID: "project::1", Module: "audio", Status: "open", EquipmentID: "equipment::hf1", Date: "2027-06-11"},
		{ID: "incident::2", Type: docType, ProjectID: "project::1", Module: "audio", Status: "in-progress", EquipmentID: "equipment::hf1", Date: "2027-06-11"},
	}}
	linker := &equipmentMock{known: map[string]bool{"equipment::hf1": true}}

	_, err := NewService(repo, nil, festival, linker).Update(scopedContext(), "project::1", "audio", "incident::1", Input{
		Title: "HF muet", Description: "Pile changée", Severity: "high", Status: "closed", EquipmentID: "equipment::hf1",
	}, "user::1", "son")

	require.NoError(t, err)
	assert.Equal(t, []stateChange{{"equipment::hf1", true, true}}, linker.changes)
}

func TestServiceUpdateMovingIncidentReconcilesBothEquipments(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Type: docType, ProjectID: "project::1", Module: "audio",
		Status: "open", EquipmentID: "equipment::hf1", Date: "2027-06-11",
	}}}
	linker := &equipmentMock{known: map[string]bool{"equipment::hf1": true, "equipment::hf2": true}}

	_, err := NewService(repo, nil, festival, linker).Update(scopedContext(), "project::1", "audio", "incident::1", Input{
		Title: "HF muet", Description: "C'était le HF 2", Severity: "high", EquipmentID: "equipment::hf2",
	}, "user::1", "son")

	require.NoError(t, err)
	assert.Equal(t, []stateChange{{"equipment::hf1", true, false}, {"equipment::hf2", false, true}}, linker.changes)
}

func TestServiceUpdateAcceptsUnchangedLinkToDeletedEquipment(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Type: docType, ProjectID: "project::1", Module: "audio",
		Status: "open", EquipmentID: "equipment::deleted", Date: "2027-06-11",
	}}}
	linker := &equipmentMock{known: map[string]bool{}}

	_, err := NewService(repo, nil, festival, linker).Update(scopedContext(), "project::1", "audio", "incident::1", Input{
		Title: "HF muet", Description: "Matériel retiré", Severity: "low", Status: "closed", EquipmentID: "equipment::deleted",
	}, "user::1", "son")

	require.NoError(t, err)
}

func TestServiceUpdateReopeningClearsResolutionDate(t *testing.T) {
	resolvedAt := time.Date(2027, 6, 11, 22, 0, 0, 0, time.UTC)
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Type: docType, ProjectID: "project::1", Module: "lighting",
		Status: "resolved", ResolvedAt: &resolvedAt, Date: "2027-06-11",
	}}}

	result, err := NewService(repo, nil, nil, nil).Update(scopedContext(), "project::1", "lighting", "incident::1", Input{
		Title: "Lyre bloquée", Description: "Le problème est revenu", Severity: "medium", Status: "open", ResolvedAt: &resolvedAt,
	}, "user::1", "lumiere")

	require.NoError(t, err)
	assert.Nil(t, result.ResolvedAt)
}

func TestServiceDeleteRestoresLinkedEquipment(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Rev: "1-rev", Type: docType, ProjectID: "project::1", Module: "audio",
		Status: "open", EquipmentID: "equipment::hf1",
	}}}
	linker := &equipmentMock{known: map[string]bool{"equipment::hf1": true}}

	err := NewService(repo, nil, festival, linker).Delete(scopedContext(), "project::1", "audio", "incident::1", "user::1", "son")

	require.NoError(t, err)
	assert.Equal(t, []stateChange{{"equipment::hf1", true, false}}, linker.changes)
}

func TestServiceListFiltersByDate(t *testing.T) {
	repo := &repositoryMock{docs: []doc{
		{ID: "incident::11", ProjectID: "project::1", Module: "audio", Date: "2027-06-11"},
		{ID: "incident::12", ProjectID: "project::1", Module: "audio", Date: "2027-06-12"},
		{ID: "incident::legacy", ProjectID: "project::1", Module: "audio", CreatedAt: time.Date(2027, 6, 11, 21, 30, 0, 0, time.UTC)},
		{ID: "incident::other-module", ProjectID: "project::1", Module: "lighting", Date: "2027-06-11"},
	}}

	result, err := NewService(repo, nil, festival, nil).List(context.Background(), "project::1", "audio", ListFilter{Date: "2027-06-11"})

	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, "incident::11", result[0].ID)
	assert.Equal(t, "incident::legacy", result[1].ID)
	assert.Equal(t, "2027-06-11", result[1].Date, "legacy incidents expose their creation day")
}

func TestServiceListRejectsMalformedDate(t *testing.T) {
	_, err := NewService(&repositoryMock{}, nil, festival, nil).List(context.Background(), "project::1", "audio", ListFilter{Date: "2027-13-01"})

	var validationError *ValidationError
	assert.ErrorAs(t, err, &validationError)
}

func TestServiceUpdateAcceptsUnchangedDateOutsideProject(t *testing.T) {
	cases := map[string]doc{
		"reported during load-in": {Date: "2027-06-08"},
		"legacy without date":     {CreatedAt: time.Date(2027, 5, 30, 9, 0, 0, 0, time.UTC)},
	}

	for name, stored := range cases {
		t.Run(name, func(t *testing.T) {
			stored.ID, stored.Type, stored.ProjectID, stored.Module, stored.Status = "incident::1", docType, "project::1", "audio", "open"
			repo := &repositoryMock{docs: []doc{stored}}

			result, err := NewService(repo, nil, festival, nil).Update(scopedContext(), "project::1", "audio", "incident::1", Input{
				Title: "Larsen", Description: "Réglé avant l'ouverture", Severity: "medium", Status: "closed",
			}, "user::1", "son")

			require.NoError(t, err)
			assert.Equal(t, "closed", result.Status)
			assert.Equal(t, stored.day(), result.Date)
		})
	}
}

func TestServiceUpdateValidatesChangedDate(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Type: docType, ProjectID: "project::1", Module: "audio", Status: "open", Date: "2027-06-11",
	}}}

	_, err := NewService(repo, nil, festival, nil).Update(scopedContext(), "project::1", "audio", "incident::1", Input{
		Title: "Larsen", Description: "Retour scène", Severity: "medium", Date: "2027-06-20",
	}, "user::1", "son")

	var validationError *ValidationError
	assert.ErrorAs(t, err, &validationError)
	assert.Nil(t, repo.updated)
}

func TestServiceUpdateKeepsResolutionDateWhenOmitted(t *testing.T) {
	resolvedAt := time.Date(2027, 6, 11, 22, 0, 0, 0, time.UTC)
	repo := &repositoryMock{docs: []doc{{
		ID: "incident::1", Type: docType, ProjectID: "project::1", Module: "lighting",
		Status: "resolved", ResolvedAt: &resolvedAt, Date: "2027-06-11",
	}}}

	result, err := NewService(repo, nil, festival, nil).Update(scopedContext(), "project::1", "lighting", "incident::1", Input{
		Title: "Lyre bloquée", Description: "Faute de frappe corrigée", Severity: "medium", Status: "closed",
	}, "user::1", "lumiere")

	require.NoError(t, err)
	require.NotNil(t, result.ResolvedAt)
	assert.Equal(t, resolvedAt, *result.ResolvedAt)
}

// concurrentResolveRepository simulates another request resolving the second
// incident of the same equipment between this request's first read and its write.
type concurrentResolveRepository struct {
	*repositoryMock
	otherID string
}

func (r *concurrentResolveRepository) Update(ctx context.Context, incident *doc) error {
	for i := range r.docs {
		if r.docs[i].ID == r.otherID {
			r.docs[i].Status = "resolved"
		}
	}
	return r.repositoryMock.Update(ctx, incident)
}

func TestServiceUpdateSeesIncidentResolvedConcurrently(t *testing.T) {
	repo := &concurrentResolveRepository{otherID: "incident::2", repositoryMock: &repositoryMock{docs: []doc{
		{ID: "incident::1", Type: docType, ProjectID: "project::1", Module: "audio", Status: "open", EquipmentID: "equipment::hf1", Date: "2027-06-11"},
		{ID: "incident::2", Type: docType, ProjectID: "project::1", Module: "audio", Status: "open", EquipmentID: "equipment::hf1", Date: "2027-06-11"},
	}}}
	linker := &equipmentMock{known: map[string]bool{"equipment::hf1": true}}

	_, err := NewService(repo, nil, festival, linker).Update(scopedContext(), "project::1", "audio", "incident::1", Input{
		Title: "HF muet", Description: "Pile changée", Severity: "high", Status: "resolved", EquipmentID: "equipment::hf1",
	}, "user::1", "son")

	require.NoError(t, err)
	assert.Equal(t, []stateChange{{"equipment::hf1", true, false}}, linker.changes,
		"the state after the write is read again, so the equipment is released")
}
