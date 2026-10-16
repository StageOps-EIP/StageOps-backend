package team

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type storeStub struct {
	created *Input
}

func (s *storeStub) List(context.Context) ([]Member, error) { return nil, nil }

func (s *storeStub) FindByID(context.Context, string) (*Member, error) { return nil, nil }

func (s *storeStub) Create(_ context.Context, input *Input) (*Member, error) {
	s.created = input
	return &Member{Name: input.Name, Email: input.Email}, nil
}

func (s *storeStub) Update(context.Context, string, *Input) (*Member, error) { return nil, nil }

func (s *storeStub) Delete(context.Context, string) error { return nil }

func TestServiceCreateDelegatesValidMember(t *testing.T) {
	store := new(storeStub)
	service := NewService(store)
	input := &Input{Name: "Mila", Email: "mila@example.com"}

	member, err := service.Create(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, "Mila", member.Name)
	assert.Same(t, input, store.created)
}

func TestServiceCreateRejectsMissingEmailBeforePersistence(t *testing.T) {
	store := new(storeStub)
	service := NewService(store)

	_, err := service.Create(context.Background(), &Input{Name: "Mila"})

	var validationErr *ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Nil(t, store.created)
}
