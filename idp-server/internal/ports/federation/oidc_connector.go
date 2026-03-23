package federation

import "context"

type OIDCAuthenticateInput struct {
	RedirectURI string
	State       string
	Code        string
	Nonce       string
}

type OIDCAuthenticateResult struct {
	Authenticated bool
	Subject       string
	Username      string
	DisplayName   string
	Email         string
	RedirectURI   string
}

type OIDCConnector interface {
	Authenticate(ctx context.Context, input OIDCAuthenticateInput) (*OIDCAuthenticateResult, error)
}
