package cache

import (
	"context"
	"time"
)

type ReplayProtectionRepository interface {
	SaveState(ctx context.Context, state string, value map[string]string, ttl time.Duration) error
	GetState(ctx context.Context, state string) (map[string]string, error)
	DeleteState(ctx context.Context, state string) error

	SaveNonce(ctx context.Context, nonce string, ttl time.Duration) error
	ExistsNonce(ctx context.Context, nonce string) (bool, error)
}
