package plugin

import "context"

type AuthnMethodType string

const (
	AuthnMethodTypePassword      AuthnMethodType = "password"
	AuthnMethodTypeFederatedOIDC AuthnMethodType = "federated_oidc"
)

type AuthenticateInput struct {
	Username    string
	Password    string
	RedirectURI string
	State       string
	Code        string
	Nonce       string
}

type AuthenticateResult struct {
	Handled         bool
	Authenticated   bool
	Subject         string
	IdentityProvider string
	Username        string
	DisplayName     string
	Email           string
	RedirectURI     string
}

type AuthnMethod interface {
	Name() string
	Type() AuthnMethodType
	Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error)
}
