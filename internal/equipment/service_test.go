package equipment

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

	items, err := NewService(repo, nil, nil).List(context.Background(), "project::1", "lighting", ListFilter{})

	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "equipment::1", items[0].ID)
}

func TestServiceGetRejectsEquipmentOutsideScope(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{ID: "equipment::1", Type: docType, ProjectID: "project::2", Module: "lighting"}}}

	_, err := NewService(repo, nil, nil).Get(context.Background(), "project::1", "lighting", "equipment::1")

	assert.ErrorIs(t, err, ErrNotFound)
}

func TestServiceCreateLightingEquipment(t *testing.T) {
	repo := &repositoryMock{}
	universe, address := 1, 100

	item, err := NewService(repo, nil, nil).Create(tenant.WithTheatreID(context.Background(), "theatre::one"), "project::1", "lighting", Input{
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

	_, err := NewService(repo, nil, nil).Create(context.Background(), "project::1", "lighting", Input{
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

	item, err := NewService(repo, nil, nil).Update(context.Background(), "project::1", "lighting", "equipment::1", Input{
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

	err := NewService(repo, nil, nil).Delete(context.Background(), "project::1", "audio", "equipment::1", "user::1", "son")

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

type calendarMock struct{ start, end string }

func (m calendarMock) DateRange(context.Context, string) (time.Time, time.Time, error) {
	start, _ := time.Parse(time.DateOnly, m.start)
	end, _ := time.Parse(time.DateOnly, m.end)
	return start, end, nil
}

var festival = calendarMock{start: "2027-06-10", end: "2027-06-14"}

func TestServiceCreatePlacesEquipmentAtOriginByDefault(t *testing.T) {
	repo := &repositoryMock{}

	item, err := NewService(repo, nil, festival).Create(tenant.WithTheatreID(context.Background(), "theatre::one"), "project::1", "audio", Input{
		Name: "HF 1", Kind: "wireless",
	}, "user::1", "son")

	require.NoError(t, err)
	assert.Equal(t, &Position{X: 0, Y: 0, Z: 0}, item.Position)
	assert.Equal(t, "ok", item.Status)
	assert.Regexp(t, `^equipment::[0-9a-f-]{36}$`, item.ID)
}

func TestServiceUpdateKeepsPositionWhenOmitted(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{
		ID: "equipment::1", Rev: "1-rev", Type: docType, ProjectID: "project::1", Module: "lighting",
		Name: "Spot 1", Kind: "fixed", Status: "ok", Position: &Position{X: 2, Y: 4, Z: 1},
	}}}

	item, err := NewService(repo, nil, festival).Update(context.Background(), "project::1", "lighting", "equipment::1", Input{
		Name: "Spot 1", Kind: "fixed", Status: "hs",
	}, "user::1", "lumiere")

	require.NoError(t, err)
	assert.Equal(t, &Position{X: 2, Y: 4, Z: 1}, item.Position)
	assert.Equal(t, "hs", item.Status)
}

func TestServiceCreateValidatesAvailabilityWindow(t *testing.T) {
	cases := map[string]Input{
		"malformed from":     {AvailableFrom: "10/06/2027"},
		"impossible to":      {AvailableTo: "2027-06-31"},
		"to before from":     {AvailableFrom: "2027-06-12", AvailableTo: "2027-06-11"},
		"before the project": {AvailableFrom: "2027-06-09"},
		"after the project":  {AvailableTo: "2027-06-15"},
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &repositoryMock{}
			input.Name, input.Kind = "Console", "console"

			_, err := NewService(repo, nil, festival).Create(tenant.WithTheatreID(context.Background(), "theatre::one"), "project::1", "audio", input, "user::1", "son")

			var validationError *ValidationError
			assert.ErrorAs(t, err, &validationError)
			assert.Nil(t, repo.created)
		})
	}
}

func TestServiceCreateStoresAvailabilityWindow(t *testing.T) {
	repo := &repositoryMock{}

	item, err := NewService(repo, nil, festival).Create(tenant.WithTheatreID(context.Background(), "theatre::one"), "project::1", "audio", Input{
		Name: "Console FOH", Kind: "console", AvailableFrom: "2027-06-11", AvailableTo: "2027-06-12",
	}, "user::1", "son")

	require.NoError(t, err)
	assert.Equal(t, "2027-06-11", item.AvailableFrom)
	assert.Equal(t, "2027-06-12", item.AvailableTo)
}

func TestServiceListFiltersByDate(t *testing.T) {
	repo := &repositoryMock{docs: []doc{
		{ID: "equipment::always", ProjectID: "project::1", Module: "lighting"},
		{ID: "equipment::from-12", ProjectID: "project::1", Module: "lighting", AvailableFrom: "2027-06-12"},
		{ID: "equipment::until-11", ProjectID: "project::1", Module: "lighting", AvailableTo: "2027-06-11"},
		{ID: "equipment::only-12", ProjectID: "project::1", Module: "lighting", AvailableFrom: "2027-06-12", AvailableTo: "2027-06-12"},
		{ID: "equipment::other-module", ProjectID: "project::1", Module: "audio"},
	}}
	service := NewService(repo, nil, festival)

	ids := func(date string) []string {
		items, err := service.List(context.Background(), "project::1", "lighting", ListFilter{Date: date})
		require.NoError(t, err)
		result := make([]string, 0, len(items))
		for _, item := range items {
			result = append(result, item.ID)
		}
		return result
	}

	assert.Equal(t, []string{"equipment::always", "equipment::until-11"}, ids("2027-06-11"))
	assert.Equal(t, []string{"equipment::always", "equipment::from-12", "equipment::only-12"}, ids("2027-06-12"))
	assert.Equal(t, []string{"equipment::always", "equipment::from-12"}, ids("2027-06-14"))
	assert.Empty(t, ids("2027-06-15"), "nothing is visible outside the project dates")
	assert.Len(t, ids(""), 4, "no date returns the whole module")
}

func TestServiceListRejectsMalformedDate(t *testing.T) {
	_, err := NewService(&repositoryMock{}, nil, festival).List(context.Background(), "project::1", "lighting", ListFilter{Date: "demain"})

	var validationError *ValidationError
	assert.ErrorAs(t, err, &validationError)
}

func TestServiceApplyIncidentState(t *testing.T) {
	cases := []struct {
		name                 string
		status               string
		hadActive, hasActive bool
		want                 string
	}{
		{"active incident flags an operational item", "ok", false, true, "to-check"},
		{"last incident closed restores the item", "to-check", true, false, "ok"},
		{"remaining incident keeps the flag", "to-check", true, true, "to-check"},
		{"manual check is not cleared by unrelated changes", "to-check", false, false, "to-check"},
		{"out of order stays out of order", "hs", false, true, "hs"},
		{"repair stays in repair", "repair", true, false, "repair"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &repositoryMock{docs: []doc{{
				ID: "equipment::1", Type: docType, ProjectID: "project::1", Module: "audio", Status: tc.status,
			}}}

			err := NewService(repo, nil, nil).ApplyIncidentState(context.Background(), "project::1", "audio", "equipment::1", tc.hadActive, tc.hasActive, "user::1", "son")

			require.NoError(t, err)
			if tc.want == tc.status {
				assert.Nil(t, repo.updated, "unchanged status must not be written")
				return
			}
			require.NotNil(t, repo.updated)
			assert.Equal(t, tc.want, repo.updated.Status)
		})
	}
}

func TestServiceExists(t *testing.T) {
	repo := &repositoryMock{docs: []doc{{ID: "equipment::1", Type: docType, ProjectID: "project::1", Module: "audio"}}}
	service := NewService(repo, nil, nil)

	found, err := service.Exists(context.Background(), "project::1", "audio", "equipment::1")
	require.NoError(t, err)
	assert.True(t, found)

	found, err = service.Exists(context.Background(), "project::1", "lighting", "equipment::1")
	require.NoError(t, err)
	assert.False(t, found, "equipment from another module is not linkable")
}
