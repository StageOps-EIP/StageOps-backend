package team

import "context"

// Store defines the persistence operations required by the team service.
type Store interface {
	List(ctx context.Context) ([]Member, error)
	FindByID(ctx context.Context, id string) (*Member, error)
	Create(ctx context.Context, input *Input) (*Member, error)
	Update(ctx context.Context, id string, input *Input) (*Member, error)
	Delete(ctx context.Context, id string) error
}

// TeamService defines the team use cases exposed to HTTP handlers.
type TeamService interface {
	List(ctx context.Context) ([]Member, error)
	Get(ctx context.Context, id string) (*Member, error)
	Create(ctx context.Context, input *Input) (*Member, error)
	Update(ctx context.Context, id string, input *Input) (*Member, error)
	Delete(ctx context.Context, id string) error
}

// Service owns team-member validation and delegates persistence to a Store.
type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) List(ctx context.Context) ([]Member, error) {
	return s.store.List(ctx)
}

func (s *Service) Get(ctx context.Context, id string) (*Member, error) {
	return s.store.FindByID(ctx, id)
}

func (s *Service) Create(ctx context.Context, input *Input) (*Member, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}
	return s.store.Create(ctx, input)
}

func (s *Service) Update(ctx context.Context, id string, input *Input) (*Member, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}
	return s.store.Update(ctx, id, input)
}

func (s *Service) Delete(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}

func validateInput(input *Input) error {
	if input.Name == "" {
		return &ValidationError{Message: "Le champ 'name' est requis."}
	}
	if input.Email == "" {
		return &ValidationError{Message: "Le champ 'email' est requis."}
	}
	return nil
}
