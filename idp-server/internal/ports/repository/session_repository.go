package repository

import (
	"context"
	"time"

	"idp-server/internal/domain/session"
)

type SessionRepository interface {
	Create(ctx context.Context, model *session.Model) error
	FindBySessionID(ctx context.Context, sessionID string) (*session.Model, error)
	ListActiveByUserID(ctx context.Context, userID int64) ([]*session.Model, error)
	LogoutBySessionID(ctx context.Context, sessionID string, loggedOutAt time.Time) error
	LogoutAllByUserID(ctx context.Context, userID int64, loggedOutAt time.Time) error
}
