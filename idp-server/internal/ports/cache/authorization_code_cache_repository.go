package cache

import (
	"context"
	"time"
)

type AuthorizationCodeCacheRepository interface {
	Save(ctx context.Context, key AuthorizationCodeCacheEntry, ttl time.Duration) error
	Get(ctx context.Context, code string) (*AuthorizationCodeCacheEntry, error)
	Delete(ctx context.Context, code string) error
	IsConsumed(ctx context.Context, code string) (bool, error)
	MarkAsConsumed(ctx context.Context, code string) error
}

type AuthorizationCodeCacheEntry struct {
	Code      string
	ClientID  string
	UserID    string
	Scope     string
	ExpiresAt time.Time
	Consumed  bool
}
