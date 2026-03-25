package authn

import (
	"errors"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserLocked         = errors.New("user is locked")
	ErrUserDisabled       = errors.New("user is disabled")
	ErrUnsupportedMethod  = errors.New("unsupported authentication method")
)

type AuthenticateInput struct {
	Method      string
	Username    string
	Password    string
	RedirectURI string
	ReturnTo    string
	State       string
	Code        string
	Nonce       string
	IPAddress   string
	UserAgent   string
}

type AuthenticateResult struct {
	SessionID       string
	UserID          int64
	Subject         string
	RedirectURI     string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
}
