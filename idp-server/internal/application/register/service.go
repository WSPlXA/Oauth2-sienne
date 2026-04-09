package register

import (
	"context"
	"net/mail"
	"regexp"
	"strings"
	"time"

	userdomain "idp-server/internal/domain/user"
	"idp-server/internal/ports/repository"
	securityport "idp-server/internal/ports/security"

	"github.com/google/uuid"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,32}$`)

type Registrar interface {
	Register(ctx context.Context, input RegisterInput) (*RegisterResult, error)
}

type PasswordResetter interface {
	AdminResetPassword(ctx context.Context, input AdminResetPasswordInput) (*AdminResetPasswordResult, error)
}

type Service struct {
	users     repository.UserRepository
	passwords securityport.PasswordVerifier
	now       func() time.Time
}

func NewService(users repository.UserRepository, passwords securityport.PasswordVerifier) *Service {
	return &Service{
		users:     users,
		passwords: passwords,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	username := strings.TrimSpace(input.Username)
	email := strings.ToLower(strings.TrimSpace(input.Email))
	displayName := strings.TrimSpace(input.DisplayName)

	switch {
	case !usernamePattern.MatchString(username):
		return nil, ErrInvalidUsername
	case !isValidEmail(email):
		return nil, ErrInvalidEmail
	case len(displayName) < 2 || len(displayName) > 128:
		return nil, ErrInvalidDisplayName
	case !isStrongEnoughPassword(input.Password):
		return nil, ErrWeakPassword
	}

	existingByUsername, err := s.users.FindByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if existingByUsername != nil {
		return nil, ErrUsernameAlreadyUsed
	}

	existingByEmail, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existingByEmail != nil {
		return nil, ErrEmailAlreadyUsed
	}

	if s.passwords == nil {
		return nil, ErrWeakPassword
	}
	passwordHash, err := s.passwords.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	now := s.now()
	status := "pending_verification"
	if input.AutoActivate {
		status = "active"
	}
	model := &userdomain.Model{
		UserUUID:         uuid.NewString(),
		Username:         username,
		Email:            email,
		EmailVerified:    input.EmailVerified,
		DisplayName:      displayName,
		PasswordHash:     passwordHash,
		Status:           status,
		FailedLoginCount: 0,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.users.Create(ctx, model); err != nil {
		return nil, err
	}

	return &RegisterResult{
		UserID:        model.ID,
		UserUUID:      model.UserUUID,
		Username:      model.Username,
		Email:         model.Email,
		EmailVerified: model.EmailVerified,
		DisplayName:   model.DisplayName,
		Status:        model.Status,
		CreatedAt:     now,
	}, nil
}

type passwordHashUpdater interface {
	UpdatePasswordHash(ctx context.Context, id int64, passwordHash string, updatedAt time.Time) error
}

func (s *Service) AdminResetPassword(ctx context.Context, input AdminResetPasswordInput) (*AdminResetPasswordResult, error) {
	if input.UserID <= 0 {
		return nil, ErrUserNotFound
	}
	if !isStrongEnoughPassword(input.NewPassword) {
		return nil, ErrWeakPassword
	}
	if s.passwords == nil {
		return nil, ErrWeakPassword
	}
	updater, ok := s.users.(passwordHashUpdater)
	if !ok {
		return nil, ErrPasswordUpdateFailed
	}

	userModel, err := s.users.FindByID(ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	if userModel == nil {
		return nil, ErrUserNotFound
	}

	passwordHash, err := s.passwords.HashPassword(input.NewPassword)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if err := updater.UpdatePasswordHash(ctx, input.UserID, passwordHash, now); err != nil {
		return nil, err
	}
	return &AdminResetPasswordResult{
		UserID:        userModel.ID,
		Username:      userModel.Username,
		PasswordSetAt: now,
	}, nil
}

func isValidEmail(email string) bool {
	if len(email) > 255 {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}

func isStrongEnoughPassword(password string) bool {
	password = strings.TrimSpace(password)
	if len(password) < 8 || len(password) > 128 {
		return false
	}

	var hasLetter, hasDigit bool
	for _, r := range password {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	return hasLetter && hasDigit
}
