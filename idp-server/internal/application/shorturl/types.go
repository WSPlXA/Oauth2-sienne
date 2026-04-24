package shorturl

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidCode       = errors.New("invalid short url code")
	ErrCodeAlreadyExists = errors.New("short url code already exists")
	ErrInvalidTargetURL  = errors.New("invalid target url")
	ErrInvalidExpiry     = errors.New("invalid short url expiry")
	ErrLinkNotFound      = errors.New("short url not found")
	ErrLinkExpired       = errors.New("short url expired")
)

type Creator interface {
	Create(ctx context.Context, input CreateInput) (*CreateResult, error)
}

type Resolver interface {
	Resolve(ctx context.Context, input ResolveInput) (*ResolveResult, error)
}

type Manager interface {
	Creator
	Resolver
}

type CreateInput struct {
	Code      string
	TargetURL string
	ExpiresAt *time.Time
}

type CreateResult struct {
	Code      string
	TargetURL string
	ExpiresAt *time.Time
	CreatedAt time.Time
}

type ResolveInput struct {
	Code string
}

type ResolveResult struct {
	Code      string
	TargetURL string
	ExpiresAt *time.Time
}
