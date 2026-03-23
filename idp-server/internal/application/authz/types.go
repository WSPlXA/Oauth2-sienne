package authz

import "errors"

var (
	ErrInvalidRequest           = errors.New("invalid request")
	ErrUnsupportedResponseType  = errors.New("unsupported response type")
	ErrInvalidClient            = errors.New("invalid client")
	ErrInvalidRedirectURI       = errors.New("invalid redirect uri")
	ErrInvalidScope             = errors.New("invalid scope")
	ErrInvalidCodeChallenge     = errors.New("invalid code challenge")
	ErrLoginRequired            = errors.New("login required")
	ErrConsentRequired          = errors.New("consent required")
)

type AuthorizationCommand struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               []string
	State               string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod string
	SessionID           string
	Nonce               string
}

type AuthorizationResult struct {
	RequireLogin   bool
	RequireConsent bool

	LoginRedirectURI   string
	ConsentRedirectURI string

	RedirectURI string
	Code        string
	State       string
}
