package cache

import (
	"context"
	"time"
)

type TokenCacheRepository interface {
	SaveAccessToken(ctx context.Context, entry AccessTokenCacheEntry, ttl time.Duration) error
	GetAccessToken(ctx context.Context, tokenSHA256 string) (*AccessTokenCacheEntry, error)

	SaveRefreshToken(ctx context.Context, entry RefreshTokenCacheEntry, ttl time.Duration) error
	GetRefreshToken(ctx context.Context, tokenSHA256 string) (*RefreshTokenCacheEntry, error)
	RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, newEntry RefreshTokenCacheEntry, newTTL time.Duration, oldRevokeTTL time.Duration) error

	RevokeAccessToken(ctx context.Context, tokenSHA256 string, ttl time.Duration) error
	RevokeRefreshToken(ctx context.Context, tokenSHA256 string, ttl time.Duration) error
	IsAccessTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error)
	IsRefreshTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error)
}

type AccessTokenCacheEntry struct {
	TokenSHA256  string
	ClientID     string
	UserID       string
	Subject      string
	ScopesJSON   string
	AudienceJSON string
	TokenType    string
	TokenFormat  string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

type RefreshTokenCacheEntry struct {
	TokenSHA256 string
	ClientID    string
	UserID      string
	Subject     string
	ScopesJSON  string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}
