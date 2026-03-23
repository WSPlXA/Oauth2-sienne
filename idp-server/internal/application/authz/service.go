package authz

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	authorizationdomain "idp-server/internal/domain/authorization"
	"idp-server/internal/ports/repository"
	pkgoauth2 "idp-server/pkg/oauth2"

	"github.com/google/uuid"
)

type Service interface {
	Authorize(ctx context.Context, cmd *AuthorizationCommand) (*AuthorizationResult, error)
}

type AuthorizationService struct {
	clients   repository.ClientRepository
	sessions  repository.SessionRepository
	codes     repository.AuthorizationCodeRepository
	consents  repository.ConsentRepository
	codeTTL   time.Duration
	now       func() time.Time
	codeMaker func() string
}

func NewService(
	clients repository.ClientRepository,
	sessions repository.SessionRepository,
	codes repository.AuthorizationCodeRepository,
	consents repository.ConsentRepository,
	codeTTL time.Duration,
) *AuthorizationService {
	return &AuthorizationService{
		clients:  clients,
		sessions: sessions,
		codes:    codes,
		consents: consents,
		codeTTL:  codeTTL,
		now: func() time.Time {
			return time.Now().UTC()
		},
		codeMaker: func() string {
			return uuid.NewString() + "." + uuid.NewString()
		},
	}
}

func (s *AuthorizationService) Authorize(ctx context.Context, cmd *AuthorizationCommand) (*AuthorizationResult, error) {
	if cmd == nil {
		return nil, ErrInvalidRequest
	}
	if strings.TrimSpace(cmd.ClientID) == "" || strings.TrimSpace(cmd.RedirectURI) == "" {
		return nil, ErrInvalidRequest
	}
	if pkgoauth2.ResponseType(strings.TrimSpace(cmd.ResponseType)) != pkgoauth2.ResponseType("code") {
		return nil, ErrUnsupportedResponseType
	}

	client, err := s.clients.FindByClientID(ctx, strings.TrimSpace(cmd.ClientID))
	if err != nil {
		return nil, err
	}
	if client == nil || client.Status != "active" {
		return nil, ErrInvalidClient
	}
	if !contains(client.GrantTypes, string(pkgoauth2.GrantTypeAuthorizationCode)) {
		return nil, ErrInvalidClient
	}
	if !contains(client.RedirectURIs, cmd.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}

	scopes := normalizeScopes(cmd.Scope)
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	if !allContained(scopes, client.Scopes) {
		return nil, ErrInvalidScope
	}
	if err := validatePKCE(client.RequirePKCE, strings.TrimSpace(cmd.CodeChallenge), strings.TrimSpace(cmd.CodeChallengeMethod)); err != nil {
		return nil, err
	}

	sessionID := strings.TrimSpace(cmd.SessionID)
	if sessionID == "" {
		return &AuthorizationResult{
			RequireLogin:     true,
			LoginRedirectURI: "/login",
		}, nil
	}

	currentSession, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if currentSession == nil || currentSession.LoggedOutAt != nil || !currentSession.ExpiresAt.After(s.now()) {
		return &AuthorizationResult{
			RequireLogin:     true,
			LoginRedirectURI: "/login",
		}, nil
	}

	if client.RequireConsent && s.consents != nil {
		hasConsent, err := s.consents.HasActiveConsent(ctx, currentSession.UserID, client.ID, scopes)
		if err != nil {
			return nil, err
		}
		if !hasConsent {
			return &AuthorizationResult{
				RequireConsent:     true,
				ConsentRedirectURI: "/consent",
			}, nil
		}
	}

	now := s.now()
	scopeJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, err
	}

	sessionDBID := currentSession.ID
	codeModel := &authorizationdomain.Model{
		Code:                s.codeMaker(),
		ClientDBID:          client.ID,
		UserID:              currentSession.UserID,
		SessionDBID:         &sessionDBID,
		RedirectURI:         cmd.RedirectURI,
		ScopesJSON:          string(scopeJSON),
		StateValue:          strings.TrimSpace(cmd.State),
		NonceValue:          strings.TrimSpace(cmd.Nonce),
		CodeChallenge:       strings.TrimSpace(cmd.CodeChallenge),
		CodeChallengeMethod: normalizeCodeChallengeMethod(cmd.CodeChallengeMethod),
		ExpiresAt:           now.Add(s.codeTTL),
	}
	if err := s.codes.Create(ctx, codeModel); err != nil {
		return nil, err
	}

	return &AuthorizationResult{
		RedirectURI: cmd.RedirectURI,
		Code:        codeModel.Code,
		State:       cmd.State,
	}, nil
}

func normalizeScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	return result
}

func allContained(values, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		allowedSet[value] = struct{}{}
	}

	for _, value := range values {
		if _, ok := allowedSet[value]; !ok {
			return false
		}
	}
	return true
}

func validatePKCE(requirePKCE bool, challenge, method string) error {
	if challenge == "" {
		if requirePKCE {
			return ErrInvalidCodeChallenge
		}
		return nil
	}

	switch normalizeCodeChallengeMethod(method) {
	case "plain", "S256":
		return nil
	default:
		return ErrInvalidCodeChallenge
	}
}

func normalizeCodeChallengeMethod(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", "PLAIN":
		return "plain"
	case "S256":
		return "S256"
	default:
		return strings.TrimSpace(method)
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
