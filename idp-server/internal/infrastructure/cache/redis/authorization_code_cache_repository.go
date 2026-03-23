package redis

import (
	"context"
	"time"

	cacheport "idp-server/internal/ports/cache"

	goredis "github.com/redis/go-redis/v9"
)

type AuthorizationCodeCacheRepository struct {
	rdb     *goredis.Client
	key     *KeyBuilder
	scripts *scriptSet
}

func NewAuthorizationCodeCacheRepository(rdb *goredis.Client, key *KeyBuilder) *AuthorizationCodeCacheRepository {
	scripts, err := loadScripts()
	if err != nil {
		panic(err)
	}

	return &AuthorizationCodeCacheRepository{
		rdb:     rdb,
		key:     key,
		scripts: scripts,
	}
}

func (r *AuthorizationCodeCacheRepository) Save(ctx context.Context, entry cacheport.AuthorizationCodeCacheEntry, ttl time.Duration) error {
	key := r.key.AuthCode(entry.Code)

	data := map[string]any{
		"client_id": entry.ClientID,
		"user_id":   entry.UserID,
		"scope":     entry.Scope,
		"expires_at": formatTime(entry.ExpiresAt),
		"consumed":  boolString(entry.Consumed),
	}

	pipe := r.rdb.TxPipeline()
	pipe.HSet(ctx, key, data)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *AuthorizationCodeCacheRepository) Get(ctx context.Context, code string) (*cacheport.AuthorizationCodeCacheEntry, error) {
	key := r.key.AuthCode(code)

	res, err := r.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, nil
	}

	expiresAt, _ := time.Parse(time.RFC3339, res["expires_at"])

	return &cacheport.AuthorizationCodeCacheEntry{
		Code:      code,
		ClientID:  res["client_id"],
		UserID:    res["user_id"],
		Scope:     res["scope"],
		ExpiresAt: expiresAt.UTC(),
		Consumed:  parseBoolString(res["consumed"]),
	}, nil
}

func (r *AuthorizationCodeCacheRepository) Delete(ctx context.Context, code string) error {
	return r.rdb.Del(ctx, r.key.AuthCode(code), r.key.AuthCodeConsumed(code)).Err()
}

func (r *AuthorizationCodeCacheRepository) IsConsumed(ctx context.Context, code string) (bool, error) {
	if value, err := r.rdb.Exists(ctx, r.key.AuthCodeConsumed(code)).Result(); err == nil && value > 0 {
		return true, nil
	}

	value, err := r.rdb.HGet(ctx, r.key.AuthCode(code), "consumed").Result()
	if err == goredis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return parseBoolString(value), nil
}

func (r *AuthorizationCodeCacheRepository) MarkAsConsumed(ctx context.Context, code string) error {
	ttl, err := r.rdb.TTL(ctx, r.key.AuthCode(code)).Result()
	if err != nil {
		return err
	}
	if ttl < 0 {
		ttl = 10 * time.Minute
	}

	_, err = runScript(
		ctx,
		r.scripts.consumeAuthorizationCode,
		r.rdb,
		[]string{
			r.key.AuthCode(code),
			r.key.AuthCodeConsumed(code),
		},
		durationSeconds(ttl),
	).Result()
	return err
}
