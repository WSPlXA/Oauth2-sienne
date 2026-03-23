package repository

import (
	"context"
	"time"

	"idp-server/internal/domain/user"
)

type UserRepository interface {
	FindByID(ctx context.Context, id int64) (*user.Model, error)
	FindByUserUUID(ctx context.Context, userUUID string) (*user.Model, error)
	FindByUsername(ctx context.Context, username string) (*user.Model, error)
	IncrementFailedLogin(ctx context.Context, id int64) (int64, error)
	ResetFailedLogin(ctx context.Context, id int64, lastLoginAt time.Time) error
}
