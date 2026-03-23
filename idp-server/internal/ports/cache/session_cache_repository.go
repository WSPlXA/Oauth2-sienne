package cache

import (
	"context"
	"time"
)

type SessionCacheRepository interface {
	Save(ctx context.Context, key SessionCacheEntry, ttl time.Duration) error
	Get(ctx context.Context, sessionID string) (*SessionCacheEntry, error)
	Delete(ctx context.Context, sessionID string) error

	AddUserSessionIndex(ctx context.Context, userID string, sessionID string, ttl time.Duration) error
	ListUserSessionIDs(ctx context.Context, userID string) ([]string, error)
	RemoveUserSessionIndex(ctx context.Context, userID string, sessionID string) error
}

type SessionCacheEntry struct {
	SessionID       string
	UserID          string
	Subject         string
	ACR             string
	AMRJSON         string
	IPAddress       string
	UserAgent       string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	Status          string
}
