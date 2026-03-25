package client_secret_post

import (
	"context"
	"strings"

	apptoken "idp-server/internal/application/token"
	pluginport "idp-server/internal/ports/plugin"
	securityport "idp-server/internal/ports/security"
)

type Authenticator struct {
	passwords securityport.PasswordVerifier
}

func NewAuthenticator(passwords securityport.PasswordVerifier) *Authenticator {
	return &Authenticator{passwords: passwords}
}

func (a *Authenticator) Name() string {
	return "client_secret_post"
}

func (a *Authenticator) Type() pluginport.ClientAuthMethodType {
	return pluginport.ClientAuthMethodClientSecretPost
}

func (a *Authenticator) Authenticate(ctx context.Context, input pluginport.ClientAuthenticateInput) (*pluginport.ClientAuthenticateResult, error) {
	_ = ctx
	if input.Client == nil || a.passwords == nil {
		return nil, apptoken.ErrInvalidClient
	}
	if strings.TrimSpace(input.AuthorizationHeader) != "" {
		return nil, apptoken.ErrInvalidClient
	}

	clientID := strings.TrimSpace(input.ClientID)
	clientSecret := input.ClientSecret
	if clientID == "" || clientSecret == "" || clientID != input.Client.ClientID {
		return nil, apptoken.ErrInvalidClient
	}
	if err := a.passwords.VerifyPassword(clientSecret, input.Client.ClientSecretHash); err != nil {
		return nil, apptoken.ErrInvalidClient
	}

	return &pluginport.ClientAuthenticateResult{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Method:       pluginport.ClientAuthMethodClientSecretPost,
	}, nil
}
