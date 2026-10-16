package events

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type storeStub struct {
	created *Input
}

func (s *storeStub) List(context.Context) ([]Event, error) { return nil, nil }

func (s *storeStub) FindByID(context.Context, string) (*Event, error) { return nil, nil }

func (s *storeStub) Create(_ context.Context, input *Input) (*Event, error) {
	s.created = input
	return &Event{Title: input.Title, Status: input.Status}, nil
}

func (s *storeStub) Update(context.Context, string, *Input) (*Event, error) { return nil, nil }

func (s *storeStub) Delete(context.Context, string) error { return nil }

func TestServiceCreateAppliesDefaultStatus(t *testing.T) {
	store := new(storeStub)
	service := NewService(store)

	event, err := service.Create(context.Background(), &Input{Title: "Balance son"})

	require.NoError(t, err)
	assert.Equal(t, "planning", event.Status)
	assert.Equal(t, "planning", store.created.Status)
}

func TestServiceCreateRejectsInvalidStatusBeforePersistence(t *testing.T) {
	store := new(storeStub)
	service := NewService(store)

	_, err := service.Create(context.Background(), &Input{Title: "Balance son", Status: "unknown"})

	assert.ErrorIs(t, err, ErrInvalidStatus)
	assert.Nil(t, store.created)
}
