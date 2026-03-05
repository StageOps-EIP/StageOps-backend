package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/audit"
	"golang.org/x/crypto/bcrypt"
)

// emailRegex validates email addresses following a practical RFC 5322 subset.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

const (
	// maxFailedAttempts is the number of wrong passwords before a lockout.
	maxFailedAttempts = 5
	// lockoutDuration is how long the account stays locked after maxFailedAttempts.
	lockoutDuration = 15 * time.Minute
)

// AuthService is the interface exposed to HTTP handlers.
type AuthService interface {
	Register(ctx context.Context, email, password string) (string, error)
	Login(ctx context.Context, email, password string) (string, error)
	GetUser(ctx context.Context, id string) (*UserPublic, error)
	UpdateUserRole(ctx context.Context, targetID, newRole, authorID, authorRole string) (*UserPublic, error)
}

// Service implements AuthService with a UserRepository and a JWT secret.
type Service struct {
	repo      UserRepository
	auditRepo audit.Repository
	jwtSecret string
}

// NewService creates a new Service. auditRepo may be nil to disable audit logging.
func NewService(repo UserRepository, auditRepo audit.Repository, jwtSecret string) *Service {
	return &Service{repo: repo, auditRepo: auditRepo, jwtSecret: jwtSecret}
}

// validateEmail returns true when email matches a practical RFC 5322 subset.
func validateEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// validatePassword enforces: min 8 chars, 1 uppercase, 1 digit, 1 special char.
func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var hasUpper, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	return hasUpper && hasDigit && hasSpecial
}

// hashPassword hashes password with bcrypt at cost 12.
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

// comparePassword returns true when password matches the bcrypt hash.
func comparePassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// Register validates input, creates a user document and returns a JWT.
func (s *Service) Register(ctx context.Context, email, password string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	if !validateEmail(email) {
		return "", &ValidationError{Message: "Format d'email invalide."}
	}
	if !validatePassword(password) {
		return "", &ValidationError{
			Message: "Le mot de passe doit contenir au moins 8 caractères, une majuscule, un chiffre et un caractère spécial.",
		}
	}

	_, err := s.repo.FindByEmail(ctx, email)
	if err == nil {
		return "", ErrEmailAlreadyExists
	}
	if !errors.Is(err, ErrUserNotFound) {
		return "", fmt.Errorf("checking email uniqueness: %w", err)
	}

	hash, err := hashPassword(password)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}

	now := time.Now().UTC()
	user := &User{
		ID:           fmt.Sprintf("user::%s", uuid.New().String()),
		Type:         "user",
		Email:        email,
		Role:         DefaultRole,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.Create(ctx, user); err != nil {
		if errors.Is(err, ErrEmailAlreadyExists) {
			return "", ErrEmailAlreadyExists
		}
		return "", fmt.Errorf("creating user: %w", err)
	}

	token, err := generateToken(user.ID, user.Email, user.Role, s.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}

	return token, nil
}

// Login checks credentials and returns a JWT on success.
// It always returns ErrInvalidCredentials for wrong email or password to
// avoid revealing which field is incorrect.
// After maxFailedAttempts wrong passwords the account is locked for lockoutDuration.
func (s *Service) Login(ctx context.Context, email, password string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("finding user: %w", err)
	}

	if user.LockedUntil != nil && time.Now().UTC().Before(*user.LockedUntil) {
		return "", ErrAccountLocked
	}

	if !comparePassword(user.PasswordHash, password) {
		s.recordFailedAttempt(ctx, user)
		return "", ErrInvalidCredentials
	}

	// Successful login: clear any previous failure counter.
	if user.FailedAttempts > 0 || user.LockedUntil != nil {
		user.FailedAttempts = 0
		user.LockedUntil = nil
		user.UpdatedAt = time.Now().UTC()
		_ = s.repo.UpdateUser(ctx, user) // best-effort: don't block a successful login
	}

	token, err := generateToken(user.ID, user.Email, user.Role, s.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}

	return token, nil
}

// recordFailedAttempt increments the failure counter and locks the account
// when maxFailedAttempts is reached. The update is best-effort.
func (s *Service) recordFailedAttempt(ctx context.Context, user *User) {
	user.FailedAttempts++
	user.UpdatedAt = time.Now().UTC()

	if user.FailedAttempts >= maxFailedAttempts {
		locked := time.Now().UTC().Add(lockoutDuration)
		user.LockedUntil = &locked
	}

	_ = s.repo.UpdateUser(ctx, user)
}

// GetUser retrieves a user by document ID and returns the public representation.
func (s *Service) GetUser(ctx context.Context, id string) (*UserPublic, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("finding user: %w", err)
	}

	return &UserPublic{
		ID:        user.ID,
		Email:     user.Email,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
	}, nil
}

// UpdateUserRole changes the role of the user identified by targetID.
// Only valid roles are accepted. The change is recorded in the audit log.
func (s *Service) UpdateUserRole(ctx context.Context, targetID, newRole, authorID, authorRole string) (*UserPublic, error) {
	if !IsValidRole(newRole) {
		return nil, &ValidationError{Message: fmt.Sprintf("Rôle invalide : %q. Valeurs acceptées : rg, lumiere, son, plateau.", newRole)}
	}

	user, err := s.repo.FindByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("finding user: %w", err)
	}

	oldRole := user.Role
	user.Role = newRole
	user.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("updating user role: %w", err)
	}

	s.logRoleChange(ctx, authorID, authorRole, targetID, oldRole, newRole)

	return &UserPublic{
		ID:        user.ID,
		Email:     user.Email,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
	}, nil
}

// logRoleChange writes a ROLE_CHANGED audit entry. Failures are swallowed
// so that an audit log error never blocks a successful role update.
func (s *Service) logRoleChange(ctx context.Context, authorID, authorRole, targetID, oldRole, newRole string) {
	if s.auditRepo == nil {
		return
	}

	payload, _ := json.Marshal(map[string]string{"before": oldRole, "after": newRole})

	entry := audit.AuditEntry{
		ID:         fmt.Sprintf("audit::%s", uuid.New().String()),
		Type:       "audit",
		Action:     audit.ActionRoleChanged,
		AuthorID:   authorID,
		AuthorRole: authorRole,
		TargetID:   targetID,
		Payload:    payload,
		CreatedAt:  time.Now().UTC(),
	}

	_ = s.auditRepo.Log(ctx, entry)
}
