package repository

import (
	"context"
	"time"
)

type ConsentRepository interface {
	HasActiveConsent(ctx context.Context, userID, clientID int64, scopes []string) (bool, error)
	UpsertActiveConsent(ctx context.Context, userID, clientID int64, scopes []string, grantedAt time.Time) error
}
