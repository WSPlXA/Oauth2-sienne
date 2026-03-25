package oidc

import (
	"context"
	"strings"

	"idp-server/internal/ports/repository"
)

type tokenValidator interface {
	ParseAndValidate(token string, opts any) (map[string]any, error)
}

type jwtValidator interface {
	ParseAndValidate(token string, opts ValidateOptions) (map[string]any, error)
}

type ValidateOptions struct {
	Issuer string
}

type UserInfoProvider interface {
	GetUserInfo(ctx context.Context, input UserInfoInput) (*UserInfoOutput, error)
}

type MetadataProvider interface {
	Discovery(ctx context.Context) (*DiscoveryDocument, error)
	JWKS(ctx context.Context) (*JSONWebKeySet, error)
}

type Service struct {
	users  repository.UserRepository
	tokens jwtValidator
	keys   jwksProvider
	issuer string
}

type jwksProvider interface {
	PublicJWKS() []JSONWebKey
}

func NewService(users repository.UserRepository, tokens jwtValidator, keys jwksProvider, issuer string) *Service {
	return &Service{
		users:  users,
		tokens: tokens,
		keys:   keys,
		issuer: issuer,
	}
}

func (s *Service) GetUserInfo(ctx context.Context, input UserInfoInput) (*UserInfoOutput, error) {
	if strings.TrimSpace(input.AccessToken) == "" {
		return nil, ErrInvalidAccessToken
	}

	claims, err := s.tokens.ParseAndValidate(input.AccessToken, ValidateOptions{
		Issuer: s.issuer,
	})
	if err != nil {
		return nil, ErrInvalidAccessToken
	}

	subject, _ := claims["sub"].(string)
	if subject == "" {
		return nil, ErrInvalidAccessToken
	}

	user, err := s.users.FindByUserUUID(ctx, subject)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	return &UserInfoOutput{
		Subject:       user.UserUUID,
		Name:          user.DisplayName,
		PreferredName: user.Username,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
	}, nil
}

func (s *Service) Discovery(ctx context.Context) (*DiscoveryDocument, error) {
	_ = ctx
	base := strings.TrimRight(s.issuer, "/")
	return &DiscoveryDocument{
		Issuer:                            base,
		AuthorizationEndpoint:             base + "/oauth2/authorize",
		TokenEndpoint:                     base + "/oauth2/token",
		UserInfoEndpoint:                  base + "/oauth2/userinfo",
		JWKSURI:                           base + "/oauth2/jwks",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token", "client_credentials"},
		CodeChallengeMethodsSupported:     []string{"plain", "S256"},
	}, nil
}

func (s *Service) JWKS(ctx context.Context) (*JSONWebKeySet, error) {
	_ = ctx
	if s.keys == nil {
		return &JSONWebKeySet{}, nil
	}
	return &JSONWebKeySet{Keys: s.keys.PublicJWKS()}, nil
}
