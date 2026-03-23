package storage

import (
	"context"
	"fmt"
	"time"

	cacheRedis "idp-server/internal/infrastructure/cache/redis"

	goredis "github.com/redis/go-redis/v9"
)

func NewRedis(ctx context.Context, addr, password string, db int) (*goredis.Client, error) {
	client := cacheRedis.NewClient(addr, password, db)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	client.Options().ReadTimeout = 3 * time.Second
	client.Options().WriteTimeout = 3 * time.Second
	if err := cacheRedis.PreloadScripts(ctx, client); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}
