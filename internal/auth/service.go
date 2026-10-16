package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/audit"
	"github.com/stageops/backend/internal/tenant"
	"golang.org/x/crypto/bcrypt"
)

// emailRegex validates email addresses following a practical RFC 5322 subset.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

const (
	// maxFailedAttempts is the number of wrong passwords before a lockout.
	maxFailedAttempts = 5
	// lockoutDuration is how long the account stays locked after maxFailedAttempts.
	lockoutDuration        = 15 * time.Minute
	defaultRefreshTTL      = 30 * 24 * time.Hour
	defaultVerificationTTL = 24 * time.Hour
)

// AuthService is the interface exposed to HTTP handlers.
type AuthService interface {
	Register(ctx context.Context, email, password string) (*TokenPair, error)
	Login(ctx context.Context, email, password string) (*TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	LogoutAll(ctx context.Context, userID string) error
	VerifyEmail(ctx context.Context, token string) (*TokenPair, error)
	ResendVerification(ctx context.Context, email string) error
	CreateOfflineGrant(ctx context.Context, userID, deviceName string) (*OfflineGrant, error)
	ListDevices(ctx context.Context, userID string) ([]DevicePublic, error)
	RevokeDevice(ctx context.Context, userID, deviceID string) error
	OfflineJWKS() map[string]interface{}
	GetUser(ctx context.Context, id string) (*UserPublic, error)
	UpdateUserRole(ctx context.Context, targetID, newRole, authorID, authorRole string) (*UserPublic, error)
	UpdateUserModules(ctx context.Context, targetID string, assignedModules []string, authorID, authorRole string) (*UserPublic, error)
}

// Service implements AuthService with a UserRepository and a JWT secret.
type Service struct {
	repo                UserRepository
	auditRepo           audit.Repository
	jwtConfig           JWTConfig
	userIDSecret        string
	registrationTheatre string
	sessions            SessionRepository
	refreshTTL          time.Duration
	mailer              VerificationMailer
	requireVerification bool
	verificationTTL     time.Duration
	devices             DeviceRepository
	offlineSigner       *OfflineSigner
}

// ServiceConfig contains security-sensitive auth configuration.
type ServiceConfig struct {
	JWT                      JWTConfig
	UserIDSecret             string
	RegistrationTheatreID    string
	SessionRepository        SessionRepository
	RefreshTTL               time.Duration
	Mailer                   VerificationMailer
	RequireEmailVerification bool
	EmailVerificationTTL     time.Duration
	DeviceRepository         DeviceRepository
	OfflineSigner            *OfflineSigner
}

// NewService creates a new Service. auditRepo may be nil to disable audit logging.
func NewService(repo UserRepository, auditRepo audit.Repository, jwtSecret string) *Service {
	return NewServiceWithConfig(repo, auditRepo, ServiceConfig{
		JWT:                   defaultJWTConfig(jwtSecret),
		UserIDSecret:          jwtSecret,
		RegistrationTheatreID: "theatre-default",
	})
}

// NewServiceWithConfig creates a service with explicit token and tenant settings.
func NewServiceWithConfig(repo UserRepository, auditRepo audit.Repository, cfg ServiceConfig) *Service {
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = defaultRefreshTTL
	}
	if cfg.EmailVerificationTTL <= 0 {
		cfg.EmailVerificationTTL = defaultVerificationTTL
	}
	return &Service{
		repo: repo, auditRepo: auditRepo, jwtConfig: cfg.JWT,
		userIDSecret: cfg.UserIDSecret, registrationTheatre: cfg.RegistrationTheatreID,
		sessions: cfg.SessionRepository, refreshTTL: cfg.RefreshTTL,
		mailer: cfg.Mailer, requireVerification: cfg.RequireEmailVerification,
		verificationTTL: cfg.EmailVerificationTTL,
		devices:         cfg.DeviceRepository, offlineSigner: cfg.OfflineSigner,
	}
}

// validateEmail returns true when email matches a practical RFC 5322 subset.
func validateEmail(email string) bool {
	return len(email) <= 254 && emailRegex.MatchString(email)
}

// validatePassword enforces bcrypt-safe length and four character classes.
func validatePassword(password string) bool {
	if len(password) < 12 || len(password) > 72 {
		return false
	}

	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	return hasLower && hasUpper && hasDigit && hasSpecial
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
func (s *Service) Register(ctx context.Context, email, password string) (*TokenPair, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	if !validateEmail(email) {
		return nil, &ValidationError{Message: "Format d'email invalide.", Fields: map[string]string{"email": "Adresse email invalide (254 caractères maximum)."}}
	}
	if !validatePassword(password) {
		return nil, &ValidationError{
			Message: "Le mot de passe ne respecte pas la politique de sécurité.",
			Fields:  map[string]string{"password": "Utilisez 12 à 72 caractères avec minuscule, majuscule, chiffre et caractère spécial."},
		}
	}

	_, err := s.repo.FindByEmail(ctx, email)
	if err == nil {
		return nil, ErrEmailAlreadyExists
	}
	if !errors.Is(err, ErrUserNotFound) {
		return nil, fmt.Errorf("checking email uniqueness: %w", err)
	}

	hash, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	now := time.Now().UTC()
	user := &User{
		ID:              emailDocumentID(email, s.userIDSecret),
		Type:            "user",
		Email:           email,
		TheatreID:       s.registrationTheatre,
		Role:            DefaultRole,
		AssignedModules: []string{DefaultRole},
		PasswordHash:    hash,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	var verificationToken string
	if s.requireVerification {
		if s.mailer == nil {
			return nil, fmt.Errorf("email verification is enabled without a mailer")
		}
		verificationToken, err = newOpaqueToken()
		if err != nil {
			return nil, err
		}
		expiresAt := now.Add(s.verificationTTL)
		user.EmailVerificationRequired = true
		user.VerificationTokenHash = hashRefreshToken(verificationToken)
		user.VerificationExpiresAt = &expiresAt
	}

	if err := s.repo.Create(ctx, user); err != nil {
		if errors.Is(err, ErrEmailAlreadyExists) {
			return nil, ErrEmailAlreadyExists
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}
	s.logAuthEvent(ctx, audit.ActionUserRegistered, user.ID, user.TheatreID, user.ID)
	if s.requireVerification {
		if err := s.mailer.SendVerification(user.Email, verificationToken); err != nil {
			return nil, fmt.Errorf("sending verification email: %w", err)
		}
		return nil, nil
	}

	tokens, err := s.issueTokenPair(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return tokens, nil
}

func emailDocumentID(email, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(email))
	return "user::" + hex.EncodeToString(mac.Sum(nil))
}

// BootstrapAdmin creates the first RG account when no RG exists yet.
// Once an RG exists, the operation is idempotent and does not inspect the
// supplied bootstrap credentials.
func (s *Service) BootstrapAdmin(ctx context.Context, email, password string) error {
	if _, err := s.repo.FindByRole(ctx, RoleRG); err == nil {
		return nil
	} else if !errors.Is(err, ErrUserNotFound) {
		return fmt.Errorf("checking existing administrator: %w", err)
	}

	email = strings.ToLower(strings.TrimSpace(email))
	if !validateEmail(email) {
		return &ValidationError{Message: "Format d'email administrateur invalide."}
	}
	if !validatePassword(password) {
		return &ValidationError{Message: "Le mot de passe administrateur ne respecte pas la politique de sécurité."}
	}

	if _, err := s.repo.FindByEmail(ctx, email); err == nil {
		return ErrEmailAlreadyExists
	} else if !errors.Is(err, ErrUserNotFound) {
		return fmt.Errorf("checking bootstrap email: %w", err)
	}

	hash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("hashing bootstrap password: %w", err)
	}
	now := time.Now().UTC()
	verifiedAt := now
	user := &User{
		ID:              emailDocumentID(email, s.userIDSecret),
		Type:            "user",
		Email:           email,
		TheatreID:       s.registrationTheatre,
		Role:            RoleRG,
		AssignedModules: []string{},
		PasswordHash:    hash,
		CreatedAt:       now,
		UpdatedAt:       now,
		EmailVerifiedAt: &verifiedAt,
	}
	if err := s.repo.Create(ctx, user); err != nil {
		if errors.Is(err, ErrEmailAlreadyExists) {
			if _, findErr := s.repo.FindByRole(ctx, RoleRG); findErr == nil {
				return nil
			}
		}
		return fmt.Errorf("creating bootstrap administrator: %w", err)
	}
	return nil
}

// Login checks credentials and returns a JWT on success.
// It always returns ErrInvalidCredentials for wrong email or password to
// avoid revealing which field is incorrect.
// After maxFailedAttempts wrong passwords the account is locked for lockoutDuration.
func (s *Service) Login(ctx context.Context, email, password string) (*TokenPair, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			s.logAuthEvent(ctx, audit.ActionLoginFailed, "", s.registrationTheatre, emailDocumentID(email, s.userIDSecret))
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("finding user: %w", err)
	}

	if user.LockedUntil != nil && time.Now().UTC().Before(*user.LockedUntil) {
		s.logAuthEvent(ctx, audit.ActionLoginFailed, user.ID, user.TheatreID, user.ID)
		return nil, ErrAccountLocked
	}
	if !comparePassword(user.PasswordHash, password) {
		s.recordFailedAttempt(ctx, user)
		s.logAuthEvent(ctx, audit.ActionLoginFailed, user.ID, user.TheatreID, user.ID)
		return nil, ErrInvalidCredentials
	}
	if user.EmailVerificationRequired && user.EmailVerifiedAt == nil {
		return nil, ErrEmailNotVerified
	}

	// Successful login: clear any previous failure counter.
	if user.FailedAttempts > 0 || user.LockedUntil != nil {
		user.FailedAttempts = 0
		user.LockedUntil = nil
		user.UpdatedAt = time.Now().UTC()
		_ = s.repo.UpdateUser(ctx, user) // best-effort: don't block a successful login
	}
	assignedModules := user.AssignedModules
	if assignedModules == nil {
		assignedModules = []string{user.Role}
	}
	user.AssignedModules = assignedModules
	tokens, err := s.issueTokenPair(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}
	s.logAuthEvent(ctx, audit.ActionLoginSucceeded, user.ID, user.TheatreID, user.ID)

	return tokens, nil
}

func (s *Service) issueTokenPair(ctx context.Context, user *User) (*TokenPair, error) {
	sessionID := "session::" + uuid.NewString()
	accessToken, err := s.generateAccessToken(user, sessionID)
	if err != nil {
		return nil, err
	}
	pair := &TokenPair{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.jwtConfig.TTL.Seconds()),
	}
	if s.sessions == nil {
		return pair, nil
	}
	refreshToken, err := newSessionRefreshToken(sessionID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	session := &Session{
		ID: sessionID, Type: "session", UserID: user.ID, TheatreID: user.TheatreID,
		RefreshTokenHash: hashRefreshToken(refreshToken), CreatedAt: now,
		LastUsedAt: now, ExpiresAt: now.Add(s.refreshTTL),
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("persisting session: %w", err)
	}
	pair.RefreshToken = refreshToken
	return pair, nil
}

// Refresh rotates a refresh token and returns a new token pair.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	if s.sessions == nil || len(refreshToken) < 32 || len(refreshToken) > 512 {
		return nil, ErrInvalidRefresh
	}
	sessionID, err := parseSessionRefreshToken(refreshToken)
	if err != nil {
		return nil, ErrInvalidRefresh
	}
	hash := hashRefreshToken(refreshToken)
	session, err := s.sessions.FindByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil, ErrInvalidRefresh
		}
		return nil, fmt.Errorf("finding session: %w", err)
	}
	now := time.Now().UTC()
	if session.RevokedAt != nil || !now.Before(session.ExpiresAt) {
		return nil, ErrInvalidRefresh
	}
	if !hmac.Equal([]byte(hash), []byte(session.RefreshTokenHash)) {
		session.RevokedAt = &now
		_ = s.sessions.Update(ctx, session)
		return nil, ErrInvalidRefresh
	}
	user, err := s.repo.FindByID(ctx, session.UserID)
	if err != nil || user.TheatreID != session.TheatreID {
		return nil, ErrInvalidRefresh
	}
	rotatedToken, err := newSessionRefreshToken(session.ID)
	if err != nil {
		return nil, err
	}
	session.PreviousRefreshHash = session.RefreshTokenHash
	session.RefreshTokenHash = hashRefreshToken(rotatedToken)
	session.LastUsedAt = now
	if err := s.sessions.Update(ctx, session); err != nil {
		return nil, fmt.Errorf("rotating session: %w", err)
	}
	accessToken, err := s.generateAccessToken(user, session.ID)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}
	pair := &TokenPair{
		AccessToken: accessToken, RefreshToken: rotatedToken,
		TokenType: "Bearer", ExpiresIn: int64(s.jwtConfig.TTL.Seconds()),
	}
	s.logAuthEvent(ctx, audit.ActionSessionRefreshed, user.ID, user.TheatreID, session.ID)
	return pair, nil
}

// Logout revokes the refresh-token family. Unknown tokens are ignored.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	if s.sessions == nil || refreshToken == "" {
		return nil
	}
	sessionID, parseErr := parseSessionRefreshToken(refreshToken)
	if parseErr != nil {
		return nil
	}
	session, err := s.sessions.FindByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil
		}
		return fmt.Errorf("finding session: %w", err)
	}
	if session.RevokedAt != nil {
		return nil
	}
	now := time.Now().UTC()
	session.RevokedAt = &now
	if err := s.sessions.Update(ctx, session); err != nil {
		return fmt.Errorf("revoking session: %w", err)
	}
	s.logAuthEvent(ctx, audit.ActionSessionRevoked, session.UserID, session.TheatreID, session.ID)
	return nil
}

// LogoutAll revokes every session belonging to the authenticated user.
func (s *Service) LogoutAll(ctx context.Context, userID string) error {
	if s.sessions == nil {
		return nil
	}
	if err := s.sessions.RevokeAllByUser(ctx, userID, time.Now().UTC()); err != nil {
		return fmt.Errorf("revoking user sessions: %w", err)
	}
	theatreID, _ := tenant.TheatreID(ctx)
	s.logAuthEvent(ctx, audit.ActionAllSessionsRevoked, userID, theatreID, userID)
	return nil
}

// VerifyEmail consumes a one-time token and starts the user's first session.
func (s *Service) VerifyEmail(ctx context.Context, token string) (*TokenPair, error) {
	if len(token) < 32 || len(token) > 512 {
		return nil, ErrInvalidVerification
	}
	hash := hashRefreshToken(token)
	user, err := s.repo.FindByVerificationHash(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidVerification
		}
		return nil, fmt.Errorf("finding email verification: %w", err)
	}
	now := time.Now().UTC()
	if user.VerificationExpiresAt == nil || !now.Before(*user.VerificationExpiresAt) ||
		!hmac.Equal([]byte(hash), []byte(user.VerificationTokenHash)) {
		return nil, ErrInvalidVerification
	}
	user.EmailVerifiedAt = &now
	user.VerificationTokenHash = ""
	user.VerificationExpiresAt = nil
	user.UpdatedAt = now
	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("marking email verified: %w", err)
	}
	s.logAuthEvent(ctx, audit.ActionEmailVerified, user.ID, user.TheatreID, user.ID)
	return s.issueTokenPair(ctx, user)
}

// ResendVerification replaces an expired or lost token without revealing account existence.
func (s *Service) ResendVerification(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if !validateEmail(email) {
		return &ValidationError{Message: "Format d'email invalide."}
	}
	if s.mailer == nil {
		return fmt.Errorf("email verification mailer is unavailable")
	}
	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil
		}
		return fmt.Errorf("finding user for verification resend: %w", err)
	}
	if !user.EmailVerificationRequired || user.EmailVerifiedAt != nil {
		return nil
	}
	token, err := newOpaqueToken()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(s.verificationTTL)
	user.VerificationTokenHash = hashRefreshToken(token)
	user.VerificationExpiresAt = &expiresAt
	user.UpdatedAt = now
	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("updating email verification: %w", err)
	}
	if err := s.mailer.SendVerification(user.Email, token); err != nil {
		return fmt.Errorf("sending verification email: %w", err)
	}
	return nil
}

func newOpaqueToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating refresh token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func newSessionRefreshToken(sessionID string) (string, error) {
	if !strings.HasPrefix(sessionID, "session::") {
		return "", fmt.Errorf("invalid session ID")
	}
	randomToken, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	return sessionID + "." + randomToken, nil
}

func parseSessionRefreshToken(token string) (string, error) {
	sessionID, randomToken, ok := strings.Cut(token, ".")
	if !ok || !strings.HasPrefix(sessionID, "session::") {
		return "", ErrInvalidRefresh
	}
	if _, err := uuid.Parse(strings.TrimPrefix(sessionID, "session::")); err != nil {
		return "", ErrInvalidRefresh
	}
	raw, err := base64.RawURLEncoding.DecodeString(randomToken)
	if err != nil || len(raw) != 32 {
		return "", ErrInvalidRefresh
	}
	return sessionID, nil
}

func hashRefreshToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// CreateOfflineGrant registers a device and signs a scoped authorization snapshot.
func (s *Service) CreateOfflineGrant(ctx context.Context, userID, deviceName string) (*OfflineGrant, error) {
	deviceName = strings.TrimSpace(deviceName)
	if len(deviceName) < 2 || len(deviceName) > 100 {
		return nil, &ValidationError{
			Message: "Nom d'appareil invalide.",
			Fields:  map[string]string{"name": "Utilisez entre 2 et 100 caractères."},
		}
	}
	if s.devices == nil || s.offlineSigner == nil {
		return nil, fmt.Errorf("offline grants are unavailable")
	}
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("finding offline user: %w", err)
	}
	theatreID, ok := tenant.TheatreID(ctx)
	if !ok || user.TheatreID != theatreID {
		return nil, ErrForbidden
	}
	now := time.Now().UTC()
	device := &Device{
		ID: "device::" + uuid.NewString(), Type: "device", UserID: user.ID,
		TheatreID: user.TheatreID, Name: deviceName, CreatedAt: now,
	}
	if err := s.devices.Create(ctx, device); err != nil {
		return nil, fmt.Errorf("registering offline device: %w", err)
	}
	token, expiresAt, err := s.offlineSigner.Sign(user, device.ID, now)
	if err != nil {
		return nil, err
	}
	grant := &OfflineGrant{
		Token: token, ExpiresAt: expiresAt,
		Device: DevicePublic{ID: device.ID, Name: device.Name, CreatedAt: device.CreatedAt},
	}
	s.logAuthEvent(ctx, audit.ActionOfflineGrantIssued, user.ID, user.TheatreID, device.ID)
	return grant, nil
}

// ListDevices returns devices belonging only to the authenticated user and theatre.
func (s *Service) ListDevices(ctx context.Context, userID string) ([]DevicePublic, error) {
	if s.devices == nil {
		return nil, fmt.Errorf("offline devices are unavailable")
	}
	theatreID, ok := tenant.TheatreID(ctx)
	if !ok {
		return nil, ErrForbidden
	}
	devices, err := s.devices.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing offline devices: %w", err)
	}
	result := make([]DevicePublic, 0, len(devices))
	for _, device := range devices {
		if device.UserID == userID && device.TheatreID == theatreID {
			result = append(result, DevicePublic{
				ID: device.ID, Name: device.Name, CreatedAt: device.CreatedAt, RevokedAt: device.RevokedAt,
			})
		}
	}
	return result, nil
}

// RevokeDevice prevents future grants for a device. Existing grants expire naturally.
func (s *Service) RevokeDevice(ctx context.Context, userID, deviceID string) error {
	if s.devices == nil {
		return fmt.Errorf("offline devices are unavailable")
	}
	device, err := s.devices.FindByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			return ErrDeviceNotFound
		}
		return fmt.Errorf("finding offline device: %w", err)
	}
	theatreID, ok := tenant.TheatreID(ctx)
	if !ok || device.UserID != userID || device.TheatreID != theatreID {
		return ErrForbidden
	}
	if device.RevokedAt != nil {
		return nil
	}
	now := time.Now().UTC()
	device.RevokedAt = &now
	if err := s.devices.Update(ctx, device); err != nil {
		return fmt.Errorf("revoking offline device: %w", err)
	}
	s.logAuthEvent(ctx, audit.ActionDeviceRevoked, userID, device.TheatreID, device.ID)
	return nil
}

// OfflineJWKS exposes only the public verification material.
func (s *Service) OfflineJWKS() map[string]interface{} {
	if s.offlineSigner == nil {
		return map[string]interface{}{"keys": []interface{}{}}
	}
	return s.offlineSigner.JWKS()
}

func (s *Service) logAuthEvent(ctx context.Context, action, authorID, theatreID, targetID string) {
	if s.auditRepo == nil {
		return
	}
	_ = s.auditRepo.Log(ctx, audit.AuditEntry{
		ID: "audit::" + uuid.NewString(), Type: "audit", TheatreID: theatreID,
		Action: action, AuthorID: authorID, TargetID: targetID, CreatedAt: time.Now().UTC(),
	})
}

func (s *Service) generateAccessToken(user *User, sessionID string) (string, error) {
	return generateAccessToken(
		user.ID, user.Email, user.Role, user.TheatreID, user.AssignedModules,
		sessionID, s.jwtConfig, time.Now().UTC(),
	)
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
		ID:              user.ID,
		Email:           user.Email,
		TheatreID:       user.TheatreID,
		Role:            user.Role,
		AssignedModules: append([]string(nil), user.AssignedModules...),
		CreatedAt:       user.CreatedAt,
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
	if theatreID, ok := tenant.TheatreID(ctx); !ok || user.TheatreID != theatreID {
		return nil, ErrForbidden
	}

	oldRole := user.Role
	user.Role = newRole
	user.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("updating user role: %w", err)
	}

	s.logRoleChange(ctx, authorID, authorRole, targetID, oldRole, newRole)

	return &UserPublic{
		ID:              user.ID,
		Email:           user.Email,
		TheatreID:       user.TheatreID,
		Role:            user.Role,
		AssignedModules: append([]string(nil), user.AssignedModules...),
		CreatedAt:       user.CreatedAt,
	}, nil
}

// UpdateUserModules replaces the operational modules assigned to a user.
func (s *Service) UpdateUserModules(ctx context.Context, targetID string, assignedModules []string, authorID, authorRole string) (*UserPublic, error) {
	modules, err := normalizeAssignedModules(assignedModules)
	if err != nil {
		return nil, err
	}

	user, err := s.repo.FindByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("finding user: %w", err)
	}
	if theatreID, ok := tenant.TheatreID(ctx); !ok || user.TheatreID != theatreID {
		return nil, ErrForbidden
	}

	previous := append([]string(nil), user.AssignedModules...)
	user.AssignedModules = modules
	user.UpdatedAt = time.Now().UTC()
	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("updating user modules: %w", err)
	}

	s.logModuleAssignment(ctx, authorID, authorRole, targetID, previous, modules)
	return &UserPublic{
		ID:              user.ID,
		Email:           user.Email,
		TheatreID:       user.TheatreID,
		Role:            user.Role,
		AssignedModules: append([]string(nil), user.AssignedModules...),
		CreatedAt:       user.CreatedAt,
	}, nil
}

func normalizeAssignedModules(input []string) ([]string, error) {
	if len(input) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]bool, len(input))
	result := make([]string, 0, len(input))
	for _, name := range input {
		normalized := normalizeModuleName(name)
		if normalized != RoleLumiere && normalized != RoleSon && normalized != RolePlateau {
			return nil, &ValidationError{Message: fmt.Sprintf("Module invalide : %q. Valeurs acceptées : lumiere, son, plateau.", name)}
		}
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result, nil
}

func (s *Service) logModuleAssignment(ctx context.Context, authorID, authorRole, targetID string, before, after []string) {
	if s.auditRepo == nil {
		return
	}
	payload, _ := json.Marshal(map[string][]string{"before": before, "after": after})
	_ = s.auditRepo.Log(ctx, audit.AuditEntry{
		ID:         fmt.Sprintf("audit::%s", uuid.NewString()),
		Type:       "audit",
		Action:     audit.ActionUserModulesUpdated,
		AuthorID:   authorID,
		AuthorRole: authorRole,
		TargetID:   targetID,
		Payload:    payload,
		CreatedAt:  time.Now().UTC(),
	})
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
