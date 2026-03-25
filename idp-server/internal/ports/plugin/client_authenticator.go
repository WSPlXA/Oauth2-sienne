package plugin

import (
	"context"

	clientdomain "idp-server/internal/domain/client"
)

type ClientAuthMethodType string

const (
	ClientAuthMethodClientSecretBasic ClientAuthMethodType = "client_secret_basic"
	ClientAuthMethodClientSecretPost  ClientAuthMethodType = "client_secret_post"
	ClientAuthMethodNone              ClientAuthMethodType = "none"
)

type ClientAuthenticateInput struct {
	Client              *clientdomain.Model
	AuthorizationHeader string
	ClientID            string
	ClientSecret        string
}

type ClientAuthenticateResult struct {
	ClientID     string
	ClientSecret string
	Method       ClientAuthMethodType
}

type ClientAuthenticator interface {
	Name() string
	Type() ClientAuthMethodType
	Authenticate(ctx context.Context, input ClientAuthenticateInput) (*ClientAuthenticateResult, error)
}
