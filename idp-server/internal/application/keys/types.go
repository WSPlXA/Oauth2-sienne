package keys

import (
	"context"
	"errors"
	"time"
)

var ErrRotateUnavailable = errors.New("key rotation is unavailable")

type RotateKeysInput struct{}

type RotateKeysResult struct {
	PreviousKID string
	ActiveKID   string
	RotatedAt   time.Time
	RotatesAt   *time.Time
}

type Manager interface {
	RotateNow(ctx context.Context, input RotateKeysInput) (*RotateKeysResult, error)
}
