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

	"github.com/google/uuid"
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

const (
	totpStepReplayTTL      = 120 * time.Second
	loginChallengeTTL      = 5 * time.Minute
	loginTOTPRedirectRoute = "/login/totp"
)

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
		now:          func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) BeginSetup(ctx context.Context, sessionID string) (*SetupResult, error) {
	authCtx, err := s.loadUser(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	existing, err := s.totps.FindByUserID(ctx, authCtx.UserID)
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
	accountName := authCtx.Email
	if strings.TrimSpace(accountName) == "" {
		accountName = authCtx.Username
	}
	provisioningURI := s.totp.ProvisioningURI(s.issuer, accountName, secret)
	ttl := s.ttl
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	now := s.now().UTC()
	if err := s.mfaCache.SaveTOTPEnrollment(ctx, cacheport.TOTPEnrollmentEntry{
		SessionID:       strings.TrimSpace(sessionID),
		UserID:          strconv.FormatInt(authCtx.UserID, 10),
		Secret:          secret,
		ProvisioningURI: provisioningURI,
		ExpiresAt:       now.Add(ttl),
	}, ttl); err != nil {
		return nil, err
	}
	return &SetupResult{
		Secret:          secret,
		ProvisioningURI: provisioningURI,
	}, nil
}

func (s *Service) ConfirmSetup(ctx context.Context, sessionID string, code string, returnTo string) (*ConfirmResult, error) {
	authCtx, err := s.loadUser(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	entry, err := s.mfaCache.GetTOTPEnrollment(ctx, strings.TrimSpace(sessionID))
	if err != nil {
		return nil, err
	}
	if entry == nil || !entry.ExpiresAt.After(now) {
		return nil, ErrEnrollmentExpired
	}
	if entry.UserID != strconv.FormatInt(authCtx.UserID, 10) {
		return nil, ErrEnrollmentExpired
	}
	if s.totp == nil {
		return nil, ErrInvalidTOTPCode
	}
	ok, matchedStep := s.totp.VerifyCodeWithStep(entry.Secret, code, now)
	if !ok {
		return nil, ErrInvalidTOTPCode
	}
	reserved, err := s.mfaCache.ReserveTOTPStepUse(ctx, strconv.FormatInt(authCtx.UserID, 10), cacheport.TOTPPurposeEnable2FA, matchedStep, totpStepReplayTTL)
	if err != nil {
		return nil, err
	}
	if !reserved {
		return nil, ErrTOTPCodeReused
	}
	if err := s.totps.Upsert(ctx, &totpdomain.Model{
		UserID:    authCtx.UserID,
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

	returnTo = strings.TrimSpace(returnTo)
	if returnTo == "" {
		return &ConfirmResult{Enabled: true}, nil
	}

	challengeID, err := s.createLoginChallenge(ctx, authCtx, returnTo, now)
	if err != nil {
		return nil, err
	}
	if err := s.invalidateCurrentSession(ctx, authCtx, now); err != nil {
		return nil, err
	}

	return &ConfirmResult{
		Enabled:        true,
		TOTPRequired:   true,
		MFAChallengeID: challengeID,
		RedirectURI:    loginTOTPRedirectRoute,
		ReturnTo:       returnTo,
	}, nil
}

func (s *Service) createLoginChallenge(ctx context.Context, authCtx mfaAuthContext, returnTo string, now time.Time) (string, error) {
	challengeID := uuid.NewString()
	err := s.mfaCache.SaveMFAChallenge(ctx, cacheport.MFAChallengeEntry{
		ChallengeID: challengeID,
		UserID:      strconv.FormatInt(authCtx.UserID, 10),
		Subject:     authCtx.Subject,
		Username:    authCtx.Username,
		IPAddress:   authCtx.IPAddress,
		UserAgent:   authCtx.UserAgent,
		ReturnTo:    returnTo,
		RedirectURI: returnTo,
		ExpiresAt:   now.Add(loginChallengeTTL),
	}, loginChallengeTTL)
	if err != nil {
		return "", err
	}
	return challengeID, nil
}

func (s *Service) invalidateCurrentSession(ctx context.Context, authCtx mfaAuthContext, now time.Time) error {
	if authCtx.SessionID == "" {
		return nil
	}
	if s.sessions != nil {
		if err := s.sessions.LogoutBySessionID(ctx, authCtx.SessionID, now); err != nil {
			return err
		}
	}
	if s.sessionCache != nil {
		if err := s.sessionCache.Delete(ctx, authCtx.SessionID); err != nil {
			return err
		}
		if err := s.sessionCache.RemoveUserSessionIndex(ctx, strconv.FormatInt(authCtx.UserID, 10), authCtx.SessionID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) loadUser(ctx context.Context, sessionID string) (mfaAuthContext, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return mfaAuthContext{}, ErrLoginRequired
	}
	now := s.now().UTC()
	if s.sessionCache != nil {
		entry, err := s.sessionCache.Get(ctx, sessionID)
		if err != nil {
			return mfaAuthContext{}, err
		}
		if entry != nil && entry.Status == "active" && entry.ExpiresAt.After(now) {
			userID, err := strconv.ParseInt(entry.UserID, 10, 64)
			if err == nil && userID > 0 {
				user, err := s.users.FindByID(ctx, userID)
				if err != nil {
					return mfaAuthContext{}, err
				}
				if user != nil {
					return mfaAuthContext{
						SessionID: sessionID,
						UserID:    userID,
						Subject:   user.UserUUID,
						Username:  user.Username,
						Email:     user.Email,
						IPAddress: entry.IPAddress,
						UserAgent: entry.UserAgent,
					}, nil
				}
			}
		}
	}
	sessionModel, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return mfaAuthContext{}, err
	}
	if sessionModel == nil || sessionModel.LoggedOutAt != nil || !sessionModel.ExpiresAt.After(now) {
		return mfaAuthContext{}, ErrLoginRequired
	}
	user, err := s.users.FindByID(ctx, sessionModel.UserID)
	if err != nil {
		return mfaAuthContext{}, err
	}
	if user == nil {
		return mfaAuthContext{}, ErrLoginRequired
	}
	subject := strings.TrimSpace(user.UserUUID)
	if subject == "" {
		subject = strings.TrimSpace(sessionModel.Subject)
	}
	return mfaAuthContext{
		SessionID: sessionID,
		UserID:    user.ID,
		Subject:   subject,
		Username:  user.Username,
		Email:     user.Email,
		IPAddress: sessionModel.IPAddress,
		UserAgent: sessionModel.UserAgent,
	}, nil
}

type mfaAuthContext struct {
	SessionID string
	UserID    int64
	Subject   string
	Username  string
	Email     string
	IPAddress string
	UserAgent string
}
