package client_secret_basic

import (
	"context"
	"encoding/base64"
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
	return "client_secret_basic"
}

func (a *Authenticator) Type() pluginport.ClientAuthMethodType {
	return pluginport.ClientAuthMethodClientSecretBasic
}

func (a *Authenticator) Authenticate(ctx context.Context, input pluginport.ClientAuthenticateInput) (*pluginport.ClientAuthenticateResult, error) {
	_ = ctx
	if input.Client == nil || a.passwords == nil {
		return nil, apptoken.ErrInvalidClient
	}
	if !strings.HasPrefix(input.AuthorizationHeader, "Basic ") {
		return nil, apptoken.ErrInvalidClient
	}
	if strings.TrimSpace(input.ClientID) != "" || strings.TrimSpace(input.ClientSecret) != "" {
		return nil, apptoken.ErrInvalidClient
	}

	payload := strings.TrimPrefix(input.AuthorizationHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, apptoken.ErrInvalidClient
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, apptoken.ErrInvalidClient
	}

	clientID := strings.TrimSpace(parts[0])
	clientSecret := parts[1]
	if clientID == "" || clientID != input.Client.ClientID {
		return nil, apptoken.ErrInvalidClient
	}
	if err := a.passwords.VerifyPassword(clientSecret, input.Client.ClientSecretHash); err != nil {
		return nil, apptoken.ErrInvalidClient
	}

	return &pluginport.ClientAuthenticateResult{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Method:       pluginport.ClientAuthMethodClientSecretBasic,
	}, nil
}
