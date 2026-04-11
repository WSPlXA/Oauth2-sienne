package plugin

import (
	"context"

	pkgoauth2 "idp-server/pkg/oauth2"
)

type GrantHandlerType = pkgoauth2.GrantType

type ExchangeInput struct {
	GrantType         pkgoauth2.GrantType
	ClientID          string
	ClientSecret      string
	ReplayFingerprint string
	Code              string
	RedirectURI       string
	CodeVerifier      string
	RefreshToken      string
	DeviceCode        string
	Username          string
	Password          string
	Scopes            []string
}

type ExchangeResult struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
	IDToken      string
}

type GrantHandler interface {
	Name() string
	Type() GrantHandlerType
	Exchange(ctx context.Context, input ExchangeInput) (*ExchangeResult, error)
}
