package repository

import (
	"context"
	"time"

	"idp-server/internal/domain/authorization"
)

type AuthorizationCodeRepository interface {
	Create(ctx context.Context, model *authorization.Model) error
	ConsumeByCode(ctx context.Context, code string, consumedAt time.Time) (*authorization.Model, error)
}
