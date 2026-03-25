package authn

import (
	"context"
	"strconv"
	"strings"
	"time"

	"idp-server/internal/domain/session"
	userdomain "idp-server/internal/domain/user"
	pluginregistry "idp-server/internal/plugins/registry"
	"idp-server/internal/ports/cache"
	pluginport "idp-server/internal/ports/plugin"
	"idp-server/internal/ports/repository"

	"github.com/google/uuid"
)

type Authenticator interface {
	Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error)
}

type Service struct {
	sessionRepo  repository.SessionRepository
	sessionCache cache.SessionCacheRepository
	userRepo     repository.UserRepository
	registry     *pluginregistry.AuthnRegistry
	sessionTTL   time.Duration
	now          func() time.Time
}

func NewService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	sessionCache cache.SessionCacheRepository,
	registry *pluginregistry.AuthnRegistry,
	sessionTTL time.Duration,
) *Service {
	return &Service{
		sessionRepo:  sessionRepo,
		sessionCache: sessionCache,
		userRepo:     userRepo,
		registry:     registry,
		sessionTTL:   sessionTTL,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (s *Service) Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error) {
	if s.registry == nil {
		return nil, ErrUnsupportedMethod
	}

	methodType, err := resolveMethodType(input)
	if err != nil {
		return nil, err
	}

	method, ok := s.registry.Get(methodType)
	if !ok || method == nil {
		return nil, ErrUnsupportedMethod
	}

	authnResult, err := method.Authenticate(ctx, pluginport.AuthenticateInput{
		Username:    input.Username,
		Password:    input.Password,
		RedirectURI: input.RedirectURI,
		ReturnTo:    input.ReturnTo,
		State:       input.State,
		Code:        input.Code,
		Nonce:       input.Nonce,
	})
	if err != nil {
		return nil, err
	}
	if authnResult != nil && authnResult.RedirectURI != "" && !authnResult.Authenticated {
		return &AuthenticateResult{
			RedirectURI: authnResult.RedirectURI,
		}, nil
	}
	if authnResult == nil || !authnResult.Handled || !authnResult.Authenticated {
		return nil, ErrInvalidCredentials
	}

	user, err := s.resolveUser(ctx, authnResult)
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

	now := s.now()
	if err := s.userRepo.ResetFailedLogin(ctx, user.ID, now); err != nil {
		return nil, err
	}

	sessionID := uuid.NewString()
	expiresAt := now.Add(s.sessionTTL)
	acr, amrJSON := sessionAuthContext(methodType)
	model := &session.Model{
		SessionID:       sessionID,
		UserID:          user.ID,
		Subject:         user.UserUUID,
		ACR:             acr,
		AMRJSON:         amrJSON,
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
		RedirectURI:     authnResult.RedirectURI,
		AuthenticatedAt: now,
		ExpiresAt:       expiresAt,
	}, nil
}

func resolveMethodType(input AuthenticateInput) (pluginport.AuthnMethodType, error) {
	method := pluginport.AuthnMethodType(strings.ToLower(strings.TrimSpace(input.Method)))
	if method != "" {
		switch method {
		case pluginport.AuthnMethodTypePassword, pluginport.AuthnMethodTypeFederatedOIDC:
			return method, nil
		default:
			return "", ErrUnsupportedMethod
		}
	}

	if strings.TrimSpace(input.Username) != "" || input.Password != "" {
		return pluginport.AuthnMethodTypePassword, nil
	}
	if strings.TrimSpace(input.Code) != "" || strings.TrimSpace(input.State) != "" || strings.TrimSpace(input.Nonce) != "" {
		return pluginport.AuthnMethodTypeFederatedOIDC, nil
	}

	return pluginport.AuthnMethodTypePassword, nil
}

func (s *Service) resolveUser(ctx context.Context, result *pluginport.AuthenticateResult) (*userdomain.Model, error) {
	if result == nil {
		return nil, nil
	}

	if subject := strings.TrimSpace(result.Subject); subject != "" {
		user, err := s.userRepo.FindByUserUUID(ctx, subject)
		if err != nil || user != nil {
			return user, err
		}
	}

	if username := strings.TrimSpace(result.Username); username != "" {
		user, err := s.userRepo.FindByUsername(ctx, username)
		if err != nil || user != nil {
			return user, err
		}
	}

	if email := strings.TrimSpace(result.Email); email != "" {
		user, err := s.userRepo.FindByEmail(ctx, email)
		if err != nil || user != nil {
			return user, err
		}
	}

	return nil, nil
}

func sessionAuthContext(methodType pluginport.AuthnMethodType) (string, string) {
	switch methodType {
	case pluginport.AuthnMethodTypeFederatedOIDC:
		return "urn:idp:acr:federated_oidc", `["federated_oidc"]`
	default:
		return "urn:idp:acr:pwd", `["pwd"]`
	}
}
