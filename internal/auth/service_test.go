package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stageops/backend/internal/audit"
	"github.com/stageops/backend/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func tenantContext() context.Context {
	return tenant.WithTheatreID(context.Background(), "theatre-default")
}

// --- Mock repository ---

type mockUserRepo struct {
	mock.Mock
}

type mockSessionRepo struct {
	mock.Mock
}

type mockDeviceRepo struct {
	mock.Mock
}

func (m *mockDeviceRepo) Create(ctx context.Context, device *Device) error {
	return m.Called(ctx, device).Error(0)
}

func (m *mockDeviceRepo) FindByID(ctx context.Context, id string) (*Device, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Device), args.Error(1)
}

func (m *mockDeviceRepo) ListByUser(ctx context.Context, userID string) ([]Device, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]Device), args.Error(1)
}

func (m *mockDeviceRepo) Update(ctx context.Context, device *Device) error {
	return m.Called(ctx, device).Error(0)
}

func (m *mockSessionRepo) Create(ctx context.Context, session *Session) error {
	return m.Called(ctx, session).Error(0)
}

func (m *mockSessionRepo) FindByID(ctx context.Context, id string) (*Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Session), args.Error(1)
}

func (m *mockSessionRepo) FindByRefreshHash(ctx context.Context, hash string) (*Session, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Session), args.Error(1)
}

func (m *mockSessionRepo) Update(ctx context.Context, session *Session) error {
	return m.Called(ctx, session).Error(0)
}

func (m *mockSessionRepo) RevokeAllByUser(ctx context.Context, userID string, revokedAt time.Time) error {
	return m.Called(ctx, userID, revokedAt).Error(0)
}

func newSessionService(repo UserRepository, sessions SessionRepository) *Service {
	return NewServiceWithConfig(repo, nil, ServiceConfig{
		JWT:          JWTConfig{Secret: "test-secret", Issuer: "test", Audience: "clients", TTL: 15 * time.Minute},
		UserIDSecret: "user-id-secret", RegistrationTheatreID: "theatre-default",
		SessionRepository: sessions, RefreshTTL: 30 * 24 * time.Hour,
	})
}

func (m *mockUserRepo) FindByEmail(ctx context.Context, email string) (*User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *mockUserRepo) FindByVerificationHash(ctx context.Context, hash string) (*User, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *mockUserRepo) FindByID(ctx context.Context, id string) (*User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *mockUserRepo) FindByRole(ctx context.Context, role string) (*User, error) {
	args := m.Called(ctx, role)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *mockUserRepo) Create(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockUserRepo) UpdateUser(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// --- Mock audit repository ---

type mockAuditRepo struct {
	mock.Mock
}

type mockVerificationMailer struct {
	mock.Mock
}

func (m *mockVerificationMailer) SendVerification(to, token string) error {
	return m.Called(to, token).Error(0)
}

func (m *mockAuditRepo) Log(ctx context.Context, entry audit.AuditEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

// --- hashPassword / comparePassword ---

func TestHashPassword(t *testing.T) {
	hash, err := hashPassword("SecurePass1!")
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	cost, err := bcrypt.Cost([]byte(hash))
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, cost, 12)
}

func TestComparePassword(t *testing.T) {
	hash, _ := hashPassword("SecurePass1!")
	assert.True(t, comparePassword(hash, "SecurePass1!"))
	assert.False(t, comparePassword(hash, "WrongPassword1!"))
}

// --- validateEmail ---

func TestValidateEmail(t *testing.T) {
	cases := []struct {
		email string
		valid bool
	}{
		{"user@example.com", true},
		{"user.name+tag@sub.domain.org", true},
		{"invalid-email", false},
		{"@nodomain.com", false},
		{"no@tld", false},
		{"", false},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.valid, validateEmail(tc.email), "email: %s", tc.email)
	}
}

// --- validatePassword ---

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		password string
		valid    bool
	}{
		{"SecurePass1!", true},
		{"ShortPass1!", false},                   // fewer than 12 characters
		{"short1!", false},                       // too short
		{"nouppercase1!", false},                 // missing uppercase
		{"NODIGITSPECIAL!", false},               // missing digit
		{"NoSpecial1Char", false},                // missing special char
		{"NoDigit!", false},                      // missing digit
		{"SECUREPASSWORD1!", false},              // missing lowercase
		{strings.Repeat("A", 70) + "a1!", false}, // exceeds bcrypt limit
		{"", false},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.valid, validatePassword(tc.password), "password: %q", tc.password)
	}
}

// --- Register ---

func TestRegister_Success(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	repo.On("FindByEmail", mock.Anything, "user@example.com").Return(nil, ErrUserNotFound)
	repo.On("Create", mock.Anything, mock.Anything).Return(nil)

	token, err := svc.Register(context.Background(), "user@example.com", "SecurePass1!")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	repo.AssertExpectations(t)
}

func TestRegisterRequiresEmailVerificationWhenEnabled(t *testing.T) {
	repo := new(mockUserRepo)
	mailer := new(mockVerificationMailer)
	svc := NewServiceWithConfig(repo, nil, ServiceConfig{
		JWT:          JWTConfig{Secret: "test-secret", Issuer: "test", Audience: "clients", TTL: 15 * time.Minute},
		UserIDSecret: "user-id-secret", RegistrationTheatreID: "theatre-default",
		Mailer: mailer, RequireEmailVerification: true, EmailVerificationTTL: time.Hour,
	})
	repo.On("FindByEmail", mock.Anything, "user@example.com").Return(nil, ErrUserNotFound)
	repo.On("Create", mock.Anything, mock.MatchedBy(func(user *User) bool {
		return user.EmailVerificationRequired && user.EmailVerifiedAt == nil &&
			user.VerificationTokenHash != "" && user.VerificationExpiresAt != nil
	})).Return(nil)
	mailer.On("SendVerification", "user@example.com", mock.MatchedBy(func(token string) bool {
		return len(token) >= 32 && token != hashRefreshToken(token)
	})).Return(nil)

	tokens, err := svc.Register(context.Background(), "user@example.com", "SecurePass1!")

	assert.NoError(t, err)
	assert.Nil(t, tokens)
	repo.AssertExpectations(t)
	mailer.AssertExpectations(t)
}

func TestVerifyEmailConsumesTokenAndCreatesSession(t *testing.T) {
	repo := new(mockUserRepo)
	sessions := new(mockSessionRepo)
	svc := newSessionService(repo, sessions)
	token := "verification-token-with-at-least-thirty-two-bytes"
	expiresAt := time.Now().Add(time.Hour)
	user := &User{
		ID: "user::one", Type: "user", Email: "user@example.com", TheatreID: "theatre-default",
		Role: RoleSon, AssignedModules: []string{RoleSon}, EmailVerificationRequired: true,
		VerificationTokenHash: hashRefreshToken(token), VerificationExpiresAt: &expiresAt,
	}
	repo.On("FindByVerificationHash", mock.Anything, hashRefreshToken(token)).Return(user, nil)
	repo.On("UpdateUser", mock.Anything, mock.MatchedBy(func(updated *User) bool {
		return updated.EmailVerifiedAt != nil && updated.VerificationTokenHash == "" && updated.VerificationExpiresAt == nil
	})).Return(nil)
	sessions.On("Create", mock.Anything, mock.AnythingOfType("*auth.Session")).Return(nil)

	tokens, err := svc.VerifyEmail(context.Background(), token)

	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	repo.AssertExpectations(t)
	sessions.AssertExpectations(t)
}

func TestLoginRejectsUnverifiedEmail(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")
	hash, err := hashPassword("SecurePass1!")
	assert.NoError(t, err)
	repo.On("FindByEmail", mock.Anything, "user@example.com").Return(&User{
		ID: "user::one", Email: "user@example.com", PasswordHash: hash,
		EmailVerificationRequired: true,
	}, nil)

	_, err = svc.Login(context.Background(), "user@example.com", "SecurePass1!")

	assert.ErrorIs(t, err, ErrEmailNotVerified)
}

func TestLoginCreatesRefreshSession(t *testing.T) {
	repo := new(mockUserRepo)
	sessions := new(mockSessionRepo)
	svc := newSessionService(repo, sessions)
	hash, err := hashPassword("SecurePass1!")
	assert.NoError(t, err)
	user := &User{
		ID: "user::one", Type: "user", Email: "user@example.com", TheatreID: "theatre-default",
		Role: RoleSon, AssignedModules: []string{RoleSon}, PasswordHash: hash,
	}
	repo.On("FindByEmail", mock.Anything, user.Email).Return(user, nil)
	sessions.On("Create", mock.Anything, mock.MatchedBy(func(session *Session) bool {
		return session.Type == "session" && session.UserID == user.ID &&
			session.TheatreID == user.TheatreID && session.RefreshTokenHash != "" &&
			session.ExpiresAt.After(session.CreatedAt)
	})).Return(nil)

	tokens, err := svc.Login(context.Background(), user.Email, "SecurePass1!")

	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.Equal(t, int64(900), tokens.ExpiresIn)
	repo.AssertExpectations(t)
	sessions.AssertExpectations(t)
}

func TestRefreshRotatesToken(t *testing.T) {
	repo := new(mockUserRepo)
	sessions := new(mockSessionRepo)
	svc := newSessionService(repo, sessions)
	refreshToken := "refresh-token-with-at-least-thirty-two-bytes"
	session := &Session{
		ID: "session::one", Rev: "1-a", Type: "session", UserID: "user::one",
		TheatreID: "theatre-default", RefreshTokenHash: hashRefreshToken(refreshToken),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	user := &User{
		ID: session.UserID, Type: "user", Email: "user@example.com", TheatreID: session.TheatreID,
		Role: RoleSon, AssignedModules: []string{RoleSon},
	}
	sessions.On("FindByRefreshHash", mock.Anything, session.RefreshTokenHash).Return(session, nil)
	repo.On("FindByID", mock.Anything, user.ID).Return(user, nil)
	sessions.On("Update", mock.Anything, mock.MatchedBy(func(updated *Session) bool {
		return updated.PreviousRefreshHash == hashRefreshToken(refreshToken) &&
			updated.RefreshTokenHash != updated.PreviousRefreshHash
	})).Return(nil)

	tokens, err := svc.Refresh(context.Background(), refreshToken)

	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEqual(t, refreshToken, tokens.RefreshToken)
	repo.AssertExpectations(t)
	sessions.AssertExpectations(t)
}

func TestRefreshRejectsReplayAndRevokesSession(t *testing.T) {
	repo := new(mockUserRepo)
	sessions := new(mockSessionRepo)
	svc := newSessionService(repo, sessions)
	replayed := "replayed-refresh-token-with-thirty-two-bytes"
	session := &Session{
		ID: "session::one", Type: "session", UserID: "user::one", TheatreID: "theatre-default",
		RefreshTokenHash: "current-hash", PreviousRefreshHash: hashRefreshToken(replayed),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	sessions.On("FindByRefreshHash", mock.Anything, hashRefreshToken(replayed)).Return(session, nil)
	sessions.On("Update", mock.Anything, mock.MatchedBy(func(updated *Session) bool {
		return updated.RevokedAt != nil
	})).Return(nil)

	_, err := svc.Refresh(context.Background(), replayed)

	assert.ErrorIs(t, err, ErrInvalidRefresh)
	sessions.AssertExpectations(t)
}

func TestCreateOfflineGrantScopesDeviceToAuthenticatedTheatre(t *testing.T) {
	repo := new(mockUserRepo)
	devices := new(mockDeviceRepo)
	signer := newTestOfflineSigner(t)
	svc := NewServiceWithConfig(repo, nil, ServiceConfig{
		JWT:          JWTConfig{Secret: "test", Issuer: "test", Audience: "clients", TTL: time.Minute},
		UserIDSecret: "secret", RegistrationTheatreID: "theatre-default",
		DeviceRepository: devices, OfflineSigner: signer,
	})
	user := &User{
		ID: "user::one", Email: "user@example.com", TheatreID: "theatre-default",
		Role: RoleSon, AssignedModules: []string{RoleSon},
	}
	repo.On("FindByID", mock.Anything, user.ID).Return(user, nil)
	devices.On("Create", mock.Anything, mock.MatchedBy(func(device *Device) bool {
		return device.UserID == user.ID && device.TheatreID == user.TheatreID && device.Name == "Console mobile"
	})).Return(nil)

	grant, err := svc.CreateOfflineGrant(tenantContext(), user.ID, " Console mobile ")

	assert.NoError(t, err)
	assert.NotEmpty(t, grant.Token)
	assert.Equal(t, "Console mobile", grant.Device.Name)
	devices.AssertExpectations(t)
}

func TestRevokeDeviceRejectsAnotherUsersDevice(t *testing.T) {
	repo := new(mockUserRepo)
	devices := new(mockDeviceRepo)
	svc := NewServiceWithConfig(repo, nil, ServiceConfig{DeviceRepository: devices})
	devices.On("FindByID", mock.Anything, "device::other").Return(&Device{
		ID: "device::other", Type: "device", UserID: "user::other", TheatreID: "theatre-default",
	}, nil)

	err := svc.RevokeDevice(tenantContext(), "user::one", "device::other")

	assert.ErrorIs(t, err, ErrForbidden)
	devices.AssertNotCalled(t, "Update")
}

func TestRegister_EmailAlreadyExists(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	existing := &User{
		ID:        "user::existing",
		Email:     "user@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	repo.On("FindByEmail", mock.Anything, "user@example.com").Return(existing, nil)

	_, err := svc.Register(context.Background(), "user@example.com", "SecurePass1!")
	assert.ErrorIs(t, err, ErrEmailAlreadyExists)
	repo.AssertExpectations(t)
}

func TestEmailDocumentIDIsStableAndDoesNotExposeEmail(t *testing.T) {
	first := emailDocumentID("user@example.com", "secret-one")
	second := emailDocumentID("user@example.com", "secret-one")
	withAnotherSecret := emailDocumentID("user@example.com", "secret-two")

	assert.Equal(t, first, second)
	assert.NotContains(t, first, "user@example.com")
	assert.NotEqual(t, first, withAnotherSecret)
}

func TestBootstrapAdminCreatesFirstRG(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")
	repo.On("FindByRole", mock.Anything, RoleRG).Return(nil, ErrUserNotFound)
	repo.On("FindByEmail", mock.Anything, "admin@example.com").Return(nil, ErrUserNotFound)
	repo.On("Create", mock.Anything, mock.MatchedBy(func(user *User) bool {
		return user.Email == "admin@example.com" && user.Role == RoleRG && comparePassword(user.PasswordHash, "SecureAdmin1!")
	})).Return(nil)

	err := svc.BootstrapAdmin(context.Background(), "ADMIN@example.com", "SecureAdmin1!")
	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestBootstrapAdminIsIdempotentWhenRGExists(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")
	repo.On("FindByRole", mock.Anything, RoleRG).Return(&User{Type: "user", Role: RoleRG}, nil)

	err := svc.BootstrapAdmin(context.Background(), "", "")
	assert.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestRegister_ValidationError_Email(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	_, err := svc.Register(context.Background(), "not-an-email", "SecurePass1!")

	var validErr *ValidationError
	assert.True(t, errors.As(err, &validErr))
}

func TestRegister_ValidationError_Password(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	_, err := svc.Register(context.Background(), "user@example.com", "weak")

	var validErr *ValidationError
	assert.True(t, errors.As(err, &validErr))
}

// --- Login ---

func TestLogin_Success(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	hash, _ := hashPassword("SecurePass1!")
	user := &User{
		ID:           "user::abc",
		Email:        "user@example.com",
		PasswordHash: hash,
	}
	repo.On("FindByEmail", mock.Anything, "user@example.com").Return(user, nil)

	token, err := svc.Login(context.Background(), "user@example.com", "SecurePass1!")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	repo.AssertExpectations(t)
}

func TestLogin_WrongPassword(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	hash, _ := hashPassword("SecurePass1!")
	user := &User{
		ID:           "user::abc",
		Email:        "user@example.com",
		PasswordHash: hash,
	}
	repo.On("FindByEmail", mock.Anything, "user@example.com").Return(user, nil)
	repo.On("UpdateUser", mock.Anything, mock.Anything).Return(nil)

	_, err := svc.Login(context.Background(), "user@example.com", "WrongPass1!")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Equal(t, 1, user.FailedAttempts)
	repo.AssertExpectations(t)
}

func TestLogin_AccountLocked(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	locked := time.Now().Add(10 * time.Minute)
	user := &User{
		ID:             "user::abc",
		Email:          "user@example.com",
		FailedAttempts: maxFailedAttempts,
		LockedUntil:    &locked,
	}
	repo.On("FindByEmail", mock.Anything, "user@example.com").Return(user, nil)

	_, err := svc.Login(context.Background(), "user@example.com", "SecurePass1!")
	assert.ErrorIs(t, err, ErrAccountLocked)
	repo.AssertExpectations(t)
}

func TestLogin_LockoutTriggeredOnMaxAttempts(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	hash, _ := hashPassword("SecurePass1!")
	user := &User{
		ID:             "user::abc",
		Email:          "user@example.com",
		PasswordHash:   hash,
		FailedAttempts: maxFailedAttempts - 1,
	}
	repo.On("FindByEmail", mock.Anything, "user@example.com").Return(user, nil)
	repo.On("UpdateUser", mock.Anything, mock.Anything).Return(nil)

	_, err := svc.Login(context.Background(), "user@example.com", "WrongPass1!")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.Equal(t, maxFailedAttempts, user.FailedAttempts)
	assert.NotNil(t, user.LockedUntil)
	assert.True(t, time.Now().Before(*user.LockedUntil))
	repo.AssertExpectations(t)
}

func TestLogin_SuccessResetsCounter(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	hash, _ := hashPassword("SecurePass1!")
	user := &User{
		ID:             "user::abc",
		Email:          "user@example.com",
		PasswordHash:   hash,
		FailedAttempts: 3,
	}
	repo.On("FindByEmail", mock.Anything, "user@example.com").Return(user, nil)
	repo.On("UpdateUser", mock.Anything, mock.Anything).Return(nil)

	token, err := svc.Login(context.Background(), "user@example.com", "SecurePass1!")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, 0, user.FailedAttempts)
	assert.Nil(t, user.LockedUntil)
	repo.AssertExpectations(t)
}

func TestLogin_UnknownEmail(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	repo.On("FindByEmail", mock.Anything, "ghost@example.com").Return(nil, ErrUserNotFound)

	_, err := svc.Login(context.Background(), "ghost@example.com", "SecurePass1!")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	repo.AssertExpectations(t)
}

// --- UpdateUserRole ---

func TestUpdateUserRole_Success(t *testing.T) {
	repo := new(mockUserRepo)
	auditRepo := new(mockAuditRepo)
	svc := NewService(repo, auditRepo, "test-secret")

	user := &User{
		ID:        "user::target",
		Email:     "target@example.com",
		TheatreID: "theatre-default",
		Role:      RolePlateau,
	}
	repo.On("FindByID", mock.Anything, "user::target").Return(user, nil)
	repo.On("UpdateUser", mock.Anything, mock.Anything).Return(nil)
	auditRepo.On("Log", mock.Anything, mock.Anything).Return(nil)

	result, err := svc.UpdateUserRole(tenantContext(), "user::target", RoleSon, "user::rg", RoleRG)
	assert.NoError(t, err)
	assert.Equal(t, RoleSon, result.Role)
	assert.Equal(t, RoleSon, user.Role) // document was mutated
	repo.AssertExpectations(t)
	auditRepo.AssertExpectations(t)
}

func TestUpdateUserRole_InvalidRole(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	_, err := svc.UpdateUserRole(context.Background(), "user::target", "superadmin", "user::rg", RoleRG)

	var validErr *ValidationError
	assert.True(t, errors.As(err, &validErr))
	repo.AssertNotCalled(t, "FindByID")
}

func TestUpdateUserRole_UserNotFound(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")

	repo.On("FindByID", mock.Anything, "user::ghost").Return(nil, ErrUserNotFound)

	_, err := svc.UpdateUserRole(context.Background(), "user::ghost", RoleSon, "user::rg", RoleRG)
	assert.ErrorIs(t, err, ErrUserNotFound)
	repo.AssertExpectations(t)
}

func TestUpdateUserRoleRejectsAnotherTheatre(t *testing.T) {
	repo := new(mockUserRepo)
	svc := NewService(repo, nil, "test-secret")
	repo.On("FindByID", mock.Anything, "user::target").Return(&User{
		ID: "user::target", TheatreID: "theatre::other", Role: RolePlateau,
	}, nil)

	_, err := svc.UpdateUserRole(tenantContext(), "user::target", RoleSon, "user::rg", RoleRG)

	assert.ErrorIs(t, err, ErrForbidden)
	repo.AssertNotCalled(t, "UpdateUser")
}

func TestUpdateUserRole_AuditLogFailureDoesNotBlockUpdate(t *testing.T) {
	repo := new(mockUserRepo)
	auditRepo := new(mockAuditRepo)
	svc := NewService(repo, auditRepo, "test-secret")

	user := &User{
		ID:        "user::target",
		Email:     "target@example.com",
		TheatreID: "theatre-default",
		Role:      RolePlateau,
	}
	repo.On("FindByID", mock.Anything, "user::target").Return(user, nil)
	repo.On("UpdateUser", mock.Anything, mock.Anything).Return(nil)
	auditRepo.On("Log", mock.Anything, mock.Anything).Return(errors.New("couch unreachable"))

	result, err := svc.UpdateUserRole(tenantContext(), "user::target", RoleSon, "user::rg", RoleRG)
	// The role update succeeded even though the audit log failed.
	assert.NoError(t, err)
	assert.Equal(t, RoleSon, result.Role)
	repo.AssertExpectations(t)
	auditRepo.AssertExpectations(t)
}

func TestUpdateUserModules_Success(t *testing.T) {
	repo := new(mockUserRepo)
	auditRepo := new(mockAuditRepo)
	svc := NewService(repo, auditRepo, "test-secret")
	user := &User{
		ID:              "user::target",
		Email:           "tech@example.com",
		TheatreID:       "theatre-default",
		Role:            RoleLumiere,
		AssignedModules: []string{RoleLumiere},
	}
	repo.On("FindByID", mock.Anything, user.ID).Return(user, nil)
	repo.On("UpdateUser", mock.Anything, mock.Anything).Return(nil)
	auditRepo.On("Log", mock.Anything, mock.MatchedBy(func(entry audit.AuditEntry) bool {
		return entry.Action == audit.ActionUserModulesUpdated && entry.TargetID == user.ID
	})).Return(nil)

	result, err := svc.UpdateUserModules(
		tenantContext(), user.ID,
		[]string{"lighting", "son", "lighting"}, "user::rg", RoleRG,
	)

	assert.NoError(t, err)
	assert.Equal(t, []string{RoleLumiere, RoleSon}, result.AssignedModules)
	repo.AssertExpectations(t)
	auditRepo.AssertExpectations(t)
}

func TestUpdateUserModules_InvalidModule(t *testing.T) {
	svc := NewService(new(mockUserRepo), nil, "test-secret")

	_, err := svc.UpdateUserModules(context.Background(), "user::target", []string{"video"}, "user::rg", RoleRG)

	var validErr *ValidationError
	assert.ErrorAs(t, err, &validErr)
}
