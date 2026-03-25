package none

import (
	"context"
	"strings"

	apptoken "idp-server/internal/application/token"
	pluginport "idp-server/internal/ports/plugin"
)

type Authenticator struct{}

func NewAuthenticator() *Authenticator {
	return &Authenticator{}
}

func (a *Authenticator) Name() string {
	return "none"
}

func (a *Authenticator) Type() pluginport.ClientAuthMethodType {
	return pluginport.ClientAuthMethodNone
}

func (a *Authenticator) Authenticate(ctx context.Context, input pluginport.ClientAuthenticateInput) (*pluginport.ClientAuthenticateResult, error) {
	_ = ctx
	if input.Client == nil {
		return nil, apptoken.ErrInvalidClient
	}
	if strings.TrimSpace(input.AuthorizationHeader) != "" {
		return nil, apptoken.ErrInvalidClient
	}
	if strings.TrimSpace(input.ClientSecret) != "" {
		return nil, apptoken.ErrInvalidClient
	}

	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" || clientID != input.Client.ClientID {
		return nil, apptoken.ErrInvalidClient
	}

	return &pluginport.ClientAuthenticateResult{
		ClientID:     clientID,
		ClientSecret: "",
		Method:       pluginport.ClientAuthMethodNone,
	}, nil
}
