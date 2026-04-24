package repository

import (
	"context"

	"idp-server/internal/domain/shorturl"
)

type ShortURLRepository interface {
	Create(ctx context.Context, link *shorturl.Link) error
	FindActiveByCode(ctx context.Context, code string) (*shorturl.Link, error)
	IncrementClick(ctx context.Context, id int64) error
}
