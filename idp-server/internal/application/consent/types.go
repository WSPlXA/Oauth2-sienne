package consent

import "errors"

var (
	ErrInvalidReturnTo = errors.New("invalid return_to")
	ErrLoginRequired   = errors.New("login required")
	ErrInvalidClient   = errors.New("invalid client")
	ErrInvalidScope    = errors.New("invalid scope")
	ErrInvalidAction   = errors.New("invalid action")
)

type PrepareInput struct {
	ReturnTo  string
	SessionID string
}

type PrepareResult struct {
	ClientID   string
	ClientName string
	Scopes     []string
	ReturnTo   string
}

type DecideInput struct {
	ReturnTo  string
	SessionID string
	Action    string
}

type DecideResult struct {
	RedirectURI string
}
