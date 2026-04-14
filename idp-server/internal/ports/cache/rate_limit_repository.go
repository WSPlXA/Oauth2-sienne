package cache

import (
	"context"
	"time"
)

type RateLimitRepository interface {
	IncrementLoginFailByUser(ctx context.Context, username, userID string, counterTTL time.Duration, lockThreshold int64, lockTTL time.Duration) (*RateLimitIncrementResult, error)
	IncrementLoginFailByIP(ctx context.Context, ip string, counterTTL time.Duration, lockThreshold int64, lockTTL time.Duration) (*RateLimitIncrementResult, error)

	GetLoginFailByUser(ctx context.Context, username string) (int64, error)
	GetLoginFailByIP(ctx context.Context, ip string) (int64, error)
	ResetLoginFailByUser(ctx context.Context, username string) error
	ResetLoginFailByIP(ctx context.Context, ip string) error
	IncrementBlacklistByUser(ctx context.Context, username, userID string, lockThreshold int64) (*RateLimitIncrementResult, error)
	ResetBlacklistByUser(ctx context.Context, username string) error

	SetUserLock(ctx context.Context, userID string, ttl time.Duration) error
	IsUserLocked(ctx context.Context, userID string) (bool, error)
	ClearUserLock(ctx context.Context, userID string) error
	IsIPLocked(ctx context.Context, ip string) (bool, error)
	ClearIPLock(ctx context.Context, ip string) error
}

type RateLimitIncrementResult struct {
	Count  int64
	Locked bool
}
