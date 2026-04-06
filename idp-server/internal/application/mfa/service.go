package mfa

import (
	"context"
	"strconv"
	"strings"
	"time"

	totpdomain "idp-server/internal/domain/totp"
	cacheport "idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
	securityport "idp-server/internal/ports/security"
)

type Service struct {
	sessions     repository.SessionRepository
	sessionCache cacheport.SessionCacheRepository
	users        repository.UserRepository
	totps        repository.TOTPRepository
	mfaCache     cacheport.MFARepository
	totp         securityport.TOTPProvider
	issuer       string
	ttl          time.Duration
	now          func() time.Time
}

func NewService(
	sessions repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
	users repository.UserRepository,
	totps repository.TOTPRepository,
	mfaCache cacheport.MFARepository,
	totp securityport.TOTPProvider,
	issuer string,
	ttl time.Duration,
) *Service {
	return &Service{
		sessions:     sessions,
		sessionCache: sessionCache,
		users:        users,
		totps:        totps,
		mfaCache:     mfaCache,
		totp:         totp,
		issuer:       strings.TrimSpace(issuer),
		ttl:          ttl,
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) BeginSetup(ctx context.Context, sessionID string) (*SetupResult, error) {
	userID, user, err := s.loadUser(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	existing, err := s.totps.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return &SetupResult{AlreadyEnabled: true}, nil
	}
	secret, err := s.totp.GenerateSecret()
	if err != nil {
		return nil, err
	}
	accountName := user.Email
	if strings.TrimSpace(accountName) == "" {
		accountName = user.Username
	}
	provisioningURI := s.totp.ProvisioningURI(s.issuer, accountName, secret)
	if s.ttl <= 0 {
		s.ttl = 10 * time.Minute
	}
	if err := s.mfaCache.SaveTOTPEnrollment(ctx, cacheport.TOTPEnrollmentEntry{
		SessionID:       strings.TrimSpace(sessionID),
		UserID:          strconv.FormatInt(userID, 10),
		Secret:          secret,
		ProvisioningURI: provisioningURI,
		ExpiresAt:       s.now().Add(s.ttl),
	}, s.ttl); err != nil {
		return nil, err
	}
	return &SetupResult{
		Secret:          secret,
		ProvisioningURI: provisioningURI,
	}, nil
}

func (s *Service) ConfirmSetup(ctx context.Context, sessionID string, code string) (*ConfirmResult, error) {
	userID, _, err := s.loadUser(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	entry, err := s.mfaCache.GetTOTPEnrollment(ctx, strings.TrimSpace(sessionID))
	if err != nil {
		return nil, err
	}
	if entry == nil || !entry.ExpiresAt.After(s.now()) {
		return nil, ErrEnrollmentExpired
	}
	if entry.UserID != strconv.FormatInt(userID, 10) {
		return nil, ErrEnrollmentExpired
	}
	if !s.totp.VerifyCode(entry.Secret, code, s.now()) {
		return nil, ErrInvalidTOTPCode
	}
	now := s.now()
	if err := s.totps.Upsert(ctx, &totpdomain.Model{
		UserID:    userID,
		Secret:    entry.Secret,
		EnabledAt: now,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		return nil, err
	}
	if err := s.mfaCache.DeleteTOTPEnrollment(ctx, strings.TrimSpace(sessionID)); err != nil {
		return nil, err
	}
	return &ConfirmResult{Enabled: true}, nil
}

func (s *Service) loadUser(ctx context.Context, sessionID string) (int64, anyUser, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return 0, anyUser{}, ErrLoginRequired
	}
	if s.sessionCache != nil {
		entry, err := s.sessionCache.Get(ctx, sessionID)
		if err != nil {
			return 0, anyUser{}, err
		}
		if entry != nil && entry.Status == "active" && entry.ExpiresAt.After(s.now()) {
			userID, err := strconv.ParseInt(entry.UserID, 10, 64)
			if err == nil && userID > 0 {
				user, err := s.users.FindByID(ctx, userID)
				if err != nil {
					return 0, anyUser{}, err
				}
				if user != nil {
					return userID, anyUser{Username: user.Username, Email: user.Email}, nil
				}
			}
		}
	}
	sessionModel, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return 0, anyUser{}, err
	}
	if sessionModel == nil || sessionModel.LoggedOutAt != nil || !sessionModel.ExpiresAt.After(s.now()) {
		return 0, anyUser{}, ErrLoginRequired
	}
	user, err := s.users.FindByID(ctx, sessionModel.UserID)
	if err != nil {
		return 0, anyUser{}, err
	}
	if user == nil {
		return 0, anyUser{}, ErrLoginRequired
	}
	return user.ID, anyUser{Username: user.Username, Email: user.Email}, nil
}

type anyUser struct {
	Username string
	Email    string
}
