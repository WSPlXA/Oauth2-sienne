package device

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidUserCode = errors.New("invalid user code")
	ErrLoginRequired   = errors.New("login required")
	ErrInvalidAction   = errors.New("invalid action")
	ErrInvalidClient   = errors.New("invalid client")
	ErrInvalidScope    = errors.New("invalid scope")
)

type Starter interface {
	Start(ctx context.Context, input StartInput) (*StartResult, error)
}

type Verifier interface {
	Prepare(ctx context.Context, input PrepareInput) (*PrepareResult, error)
	Decide(ctx context.Context, input DecideInput) (*DecideResult, error)
}

type StartInput struct {
	ClientID string
	Scopes   []string
}

type StartResult struct {
	DeviceCode string
	UserCode   string
	ExpiresAt  time.Time
	Interval   int64
	ClientID   string
}

type PrepareInput struct {
	SessionID string
	UserCode  string
}

type PrepareResult struct {
	UserCode   string
	ClientID   string
	ClientName string
	Scopes     []string
}

type DecideInput struct {
	SessionID string
	UserCode  string
	Action    string
}

type DecideResult struct {
	Approved bool
}
