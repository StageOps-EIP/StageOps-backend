package events

import "context"

// Store defines the persistence operations required by the event service.
type Store interface {
	List(ctx context.Context) ([]Event, error)
	FindByID(ctx context.Context, id string) (*Event, error)
	Create(ctx context.Context, input *Input) (*Event, error)
	Update(ctx context.Context, id string, input *Input) (*Event, error)
	Delete(ctx context.Context, id string) error
}

// EventService defines the event use cases exposed to HTTP handlers.
type EventService interface {
	List(ctx context.Context) ([]Event, error)
	Get(ctx context.Context, id string) (*Event, error)
	Create(ctx context.Context, input *Input) (*Event, error)
	Update(ctx context.Context, id string, input *Input) (*Event, error)
	Delete(ctx context.Context, id string) error
}

// Service owns event validation and delegates persistence to a Store.
type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) List(ctx context.Context) ([]Event, error) {
	return s.store.List(ctx)
}

func (s *Service) Get(ctx context.Context, id string) (*Event, error) {
	return s.store.FindByID(ctx, id)
}

func (s *Service) Create(ctx context.Context, input *Input) (*Event, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}
	return s.store.Create(ctx, input)
}

func (s *Service) Update(ctx context.Context, id string, input *Input) (*Event, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}
	return s.store.Update(ctx, id, input)
}

func (s *Service) Delete(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}

func validateInput(input *Input) error {
	if input.Title == "" {
		return &ValidationError{Message: "Le champ 'title' est requis."}
	}
	if input.Status != "" && !validStatuses[input.Status] {
		return ErrInvalidStatus
	}
	if input.Status == "" {
		input.Status = "planning"
	}
	return nil
}
