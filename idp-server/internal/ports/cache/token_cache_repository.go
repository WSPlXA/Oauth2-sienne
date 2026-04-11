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
	CheckRefreshTokenReplay(ctx context.Context, tokenSHA256 string, replayFingerprint string) (*RefreshTokenReplayResult, error)
	RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, newEntry RefreshTokenCacheEntry, response TokenResponseCacheEntry, replayFingerprint string, newTTL time.Duration, graceTTL time.Duration) error

	RevokeAccessToken(ctx context.Context, tokenSHA256 string, ttl time.Duration) error
	RevokeRefreshToken(ctx context.Context, tokenSHA256 string, ttl time.Duration) error
	IsAccessTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error)
	IsRefreshTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error)
}

type RefreshTokenReplayStatus string

const (
	RefreshTokenReplayNone     RefreshTokenReplayStatus = "none"
	RefreshTokenReplayGrace    RefreshTokenReplayStatus = "grace"
	RefreshTokenReplayRejected RefreshTokenReplayStatus = "rejected"
)

type RefreshTokenReplayResult struct {
	Status   RefreshTokenReplayStatus
	Response *TokenResponseCacheEntry
}

type TokenResponseCacheEntry struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
	IDToken      string
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
	FamilyID    string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}
