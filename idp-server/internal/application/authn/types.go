package authn

import (
	"errors"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserLocked         = errors.New("user is locked")
	ErrUserDisabled       = errors.New("user is disabled")
)

type AuthenticateInput struct {
	Username  string
	Password  string
	IPAddress string
	UserAgent string
}

type AuthenticateResult struct {
	SessionID       string
	UserID          int64
	Subject         string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
}
