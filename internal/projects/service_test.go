package projects

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stageops/backend/internal/audit"
	"github.com/stageops/backend/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type repositoryMock struct {
	listFn   func(context.Context) ([]Project, error)
	findFn   func(context.Context, string) (*Project, error)
	createFn func(context.Context, *Project) error
	updateFn func(context.Context, *Project) error
	deleteFn func(context.Context, string, string) error
}

func (m *repositoryMock) List(ctx context.Context) ([]Project, error) {
	return m.listFn(ctx)
}

func (m *repositoryMock) FindByID(ctx context.Context, id string) (*Project, error) {
	return m.findFn(ctx, id)
}

func (m *repositoryMock) Create(ctx context.Context, project *Project) error {
	return m.createFn(ctx, project)
}

func (m *repositoryMock) Update(ctx context.Context, project *Project) error {
	return m.updateFn(ctx, project)
}

func (m *repositoryMock) Delete(ctx context.Context, id, rev string) error {
	return m.deleteFn(ctx, id, rev)
}

type auditMock struct {
	entries []audit.AuditEntry
	err     error
}

func (m *auditMock) Log(_ context.Context, entry audit.AuditEntry) error {
	m.entries = append(m.entries, entry)
	return m.err
}

func TestServiceList(t *testing.T) {
	repo := &repositoryMock{listFn: func(context.Context) ([]Project, error) {
		return []Project{{ID: "project::1", Name: "Festival"}}, nil
	}}

	result, err := NewService(repo, nil).List(context.Background())

	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "project::1", result[0].ID)
	assert.Equal(t, "Festival", result[0].Name)
}

func TestServiceGetPropagatesNotFound(t *testing.T) {
	repo := &repositoryMock{findFn: func(context.Context, string) (*Project, error) {
		return nil, ErrNotFound
	}}

	_, err := NewService(repo, nil).Get(context.Background(), "project::missing")

	assert.ErrorIs(t, err, ErrNotFound)
}

func TestServiceCreateDefaultsModulesAndLogs(t *testing.T) {
	var stored *Project
	repo := &repositoryMock{createFn: func(_ context.Context, project *Project) error {
		stored = project
		return nil
	}}
	audits := &auditMock{err: errors.New("audit unavailable")}
	service := NewService(repo, audits)

	result, err := service.Create(tenant.WithTheatreID(context.Background(), "theatre::one"), CreateInput{
		Name:      " Festival ",
		Venue:     " Arena ",
		StartDate: "2027-06-10",
		EndDate:   "2027-06-12",
	}, "user::1", "rg")

	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "project", stored.Type)
	assert.Equal(t, "Festival", result.Name)
	assert.Equal(t, "Arena", result.Venue)
	assert.True(t, result.ModulesConfig.Lighting)
	assert.True(t, result.ModulesConfig.Audio)
	assert.True(t, result.ModulesConfig.Stage)
	assert.WithinDuration(t, time.Now().UTC(), result.CreatedAt, time.Second)
	require.Len(t, audits.entries, 1)
	assert.Equal(t, ActionProjectCreated, audits.entries[0].Action)
	assert.Equal(t, result.ID, audits.entries[0].TargetID)
}

func TestServiceCreateRejectsInvalidDateRange(t *testing.T) {
	repo := &repositoryMock{createFn: func(context.Context, *Project) error {
		t.Fatal("repository must not be called")
		return nil
	}}

	_, err := NewService(repo, nil).Create(context.Background(), CreateInput{
		Name:      "Festival",
		Venue:     "Arena",
		StartDate: "2027-06-12",
		EndDate:   "2027-06-10",
	}, "user::1", "rg")

	var validationError *ValidationError
	assert.ErrorAs(t, err, &validationError)
}

func TestServiceUpdateAppliesPartialInput(t *testing.T) {
	project := validProject()
	var stored *Project
	repo := &repositoryMock{
		findFn: func(context.Context, string) (*Project, error) { return project, nil },
		updateFn: func(_ context.Context, project *Project) error {
			stored = project
			return nil
		},
	}
	audits := &auditMock{}
	name := "New name"
	modules := ModulesConfig{Lighting: true, Audio: false, Stage: false}

	result, err := NewService(repo, audits).Update(context.Background(), project.ID, UpdateInput{
		Name:          &name,
		ModulesConfig: &modules,
	}, "user::1", "rg")

	require.NoError(t, err)
	assert.Equal(t, "New name", stored.Name)
	assert.Equal(t, "Paris", stored.Venue)
	assert.False(t, result.ModulesConfig.Audio)
	assert.True(t, result.UpdatedAt.After(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)))
	require.Len(t, audits.entries, 1)
	assert.Equal(t, ActionProjectUpdated, audits.entries[0].Action)
}

func TestServiceDeleteUsesCurrentRevision(t *testing.T) {
	project := validProject()
	var deletedID, deletedRev string
	repo := &repositoryMock{
		findFn: func(context.Context, string) (*Project, error) { return project, nil },
		deleteFn: func(_ context.Context, id, rev string) error {
			deletedID, deletedRev = id, rev
			return nil
		},
	}

	err := NewService(repo, nil).Delete(context.Background(), project.ID, "user::1", "rg")

	require.NoError(t, err)
	assert.Equal(t, project.ID, deletedID)
	assert.Equal(t, "2-revision", deletedRev)
}

func TestServiceIsModuleActiveSupportsDomainAliases(t *testing.T) {
	repo := &repositoryMock{findFn: func(context.Context, string) (*Project, error) {
		project := validProject()
		project.ModulesConfig = ModulesConfig{Lighting: true, Audio: false, Stage: true}
		return project, nil
	}}
	service := NewService(repo, nil)

	lighting, err := service.IsModuleActive(context.Background(), "project::1", "lumiere")
	require.NoError(t, err)
	assert.True(t, lighting)

	audio, err := service.IsModuleActive(context.Background(), "project::1", "audio")
	require.NoError(t, err)
	assert.False(t, audio)

	_, err = service.IsModuleActive(context.Background(), "project::1", "video")
	var validationError *ValidationError
	assert.ErrorAs(t, err, &validationError)
}

func TestServiceCreateRequiresNameVenueAndDates(t *testing.T) {
	repo := &repositoryMock{createFn: func(context.Context, *Project) error {
		t.Fatal("repository must not be called")
		return nil
	}}
	valid := CreateInput{Name: "Festival", Venue: "Arena", StartDate: "2027-06-10", EndDate: "2027-06-12"}
	cases := map[string]func(*CreateInput){
		"blank name":       func(input *CreateInput) { input.Name = "   " },
		"blank venue":      func(input *CreateInput) { input.Venue = "" },
		"missing start":    func(input *CreateInput) { input.StartDate = "" },
		"malformed end":    func(input *CreateInput) { input.EndDate = "12/06/2027" },
		"impossible date":  func(input *CreateInput) { input.StartDate = "2027-02-30" },
		"end before start": func(input *CreateInput) { input.EndDate = "2027-06-09" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := valid
			mutate(&input)

			_, err := NewService(repo, nil).Create(tenant.WithTheatreID(context.Background(), "theatre::one"), input, "user::1", "rg")

			var validationError *ValidationError
			assert.ErrorAs(t, err, &validationError)
		})
	}
}

func TestServiceCreateKeepsCustomModuleSelection(t *testing.T) {
	var stored *Project
	repo := &repositoryMock{createFn: func(_ context.Context, project *Project) error {
		stored = project
		return nil
	}}

	result, err := NewService(repo, nil).Create(tenant.WithTheatreID(context.Background(), "theatre::one"), CreateInput{
		Name: "Concert", Venue: "Zénith", StartDate: "2027-06-10", EndDate: "2027-06-10",
		ModulesConfig: &ModulesConfig{Lighting: true, Audio: false, Stage: false},
	}, "user::1", "rg")

	require.NoError(t, err)
	assert.Equal(t, ModulesConfig{Lighting: true}, stored.ModulesConfig)
	assert.Equal(t, ModulesConfig{Lighting: true}, result.ModulesConfig)
	assert.Equal(t, "theatre::one", stored.TheatreID)
}

func TestServiceDateRange(t *testing.T) {
	repo := &repositoryMock{findFn: func(context.Context, string) (*Project, error) {
		return validProject(), nil
	}}

	start, end, err := NewService(repo, nil).DateRange(context.Background(), "project::1")

	require.NoError(t, err)
	assert.Equal(t, time.Date(2027, 6, 10, 0, 0, 0, 0, time.UTC), start)
	assert.Equal(t, time.Date(2027, 6, 12, 0, 0, 0, 0, time.UTC), end)
}

func TestServiceDateRangePropagatesNotFound(t *testing.T) {
	repo := &repositoryMock{findFn: func(context.Context, string) (*Project, error) {
		return nil, ErrNotFound
	}}

	_, _, err := NewService(repo, nil).DateRange(context.Background(), "project::missing")

	assert.ErrorIs(t, err, ErrNotFound)
}

func validProject() *Project {
	return &Project{
		ID:        "project::1",
		Rev:       "2-revision",
		Type:      docType,
		Name:      "Festival",
		Venue:     "Paris",
		StartDate: "2027-06-10",
		EndDate:   "2027-06-12",
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}
