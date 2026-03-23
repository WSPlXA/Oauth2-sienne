package repository

import (
	"context"

	"idp-server/internal/domain/client"
)

type ClientRepository interface {
	FindByClientID(ctx context.Context, clientID string) (*client.Model, error)
}
