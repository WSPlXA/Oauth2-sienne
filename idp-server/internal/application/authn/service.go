package authn

import (
	"context"
	"strconv"
	"strings"
	"time"

	"idp-server/internal/domain/session"
	"idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
	securityport "idp-server/internal/ports/security"

	"github.com/google/uuid"
)

type Authenticator interface {
	Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error)
}

type Service struct {
	sessionRepo  repository.SessionRepository
	sessionCache cache.SessionCacheRepository
	userRepo     repository.UserRepository
	passwords    securityport.PasswordVerifier
	sessionTTL   time.Duration
}

func NewService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	sessionCache cache.SessionCacheRepository,
	passwords securityport.PasswordVerifier,
	sessionTTL time.Duration,
) *Service {
	return &Service{
		sessionRepo:  sessionRepo,
		sessionCache: sessionCache,
		userRepo:     userRepo,
		passwords:    passwords,
		sessionTTL:   sessionTTL,
	}
}

func (s *Service) Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error) {
	username := strings.TrimSpace(input.Username)
	if username == "" || input.Password == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := s.userRepo.FindByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}
	if user.Status == "locked" {
		return nil, ErrUserLocked
	}
	if user.Status != "" && user.Status != "active" {
		return nil, ErrUserDisabled
	}

	if err := s.passwords.VerifyPassword(input.Password, user.PasswordHash); err != nil {
		if _, incErr := s.userRepo.IncrementFailedLogin(ctx, user.ID); incErr != nil {
			return nil, incErr
		}
		return nil, ErrInvalidCredentials
	}

	now := time.Now().UTC()
	if err := s.userRepo.ResetFailedLogin(ctx, user.ID, now); err != nil {
		return nil, err
	}

	sessionID := uuid.NewString()
	expiresAt := now.Add(s.sessionTTL)
	model := &session.Model{
		SessionID:       sessionID,
		UserID:          user.ID,
		Subject:         user.UserUUID,
		ACR:             "urn:idp:acr:pwd",
		AMRJSON:         `["pwd"]`,
		IPAddress:       input.IPAddress,
		UserAgent:       input.UserAgent,
		AuthenticatedAt: now,
		ExpiresAt:       expiresAt,
	}
	if err := s.sessionRepo.Create(ctx, model); err != nil {
		return nil, err
	}

	if s.sessionCache != nil {
		cacheEntry := cache.SessionCacheEntry{
			SessionID:       sessionID,
			UserID:          strconv.FormatInt(user.ID, 10),
			Subject:         user.UserUUID,
			ACR:             model.ACR,
			AMRJSON:         model.AMRJSON,
			IPAddress:       input.IPAddress,
			UserAgent:       input.UserAgent,
			AuthenticatedAt: now,
			ExpiresAt:       expiresAt,
			Status:          "active",
		}
		if err := s.sessionCache.Save(ctx, cacheEntry, s.sessionTTL); err != nil {
			return nil, err
		}
	}

	return &AuthenticateResult{
		SessionID:       sessionID,
		UserID:          user.ID,
		Subject:         user.UserUUID,
		AuthenticatedAt: now,
		ExpiresAt:       expiresAt,
	}, nil
}
