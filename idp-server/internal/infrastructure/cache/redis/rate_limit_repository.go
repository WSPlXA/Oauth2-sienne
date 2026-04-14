package redis

import (
	"context"
	"strings"
	"time"

	cacheport "idp-server/internal/ports/cache"

	goredis "github.com/redis/go-redis/v9"
)

type RateLimitRepository struct {
	rdb     *goredis.Client
	key     *KeyBuilder
	scripts *scriptSet
}

func NewRateLimitRepository(rdb *goredis.Client, key *KeyBuilder) *RateLimitRepository {
	scripts, err := loadScripts()
	if err != nil {
		panic(err)
	}

	return &RateLimitRepository{
		rdb:     rdb,
		key:     key,
		scripts: scripts,
	}
}

func (r *RateLimitRepository) IncrementLoginFailByUser(
	ctx context.Context,
	username, userID string,
	counterTTL time.Duration,
	lockThreshold int64,
	lockTTL time.Duration,
) (*cacheport.RateLimitIncrementResult, error) {
	key := r.key.LoginFailUser(username)
	lockKey := ""
	if strings.TrimSpace(userID) != "" {
		lockKey = r.key.UserLock(strings.TrimSpace(userID))
	}

	return r.incrementWithLock(ctx, key, lockKey, counterTTL, lockThreshold, lockTTL)
}

func (r *RateLimitRepository) IncrementLoginFailByIP(
	ctx context.Context,
	ip string,
	counterTTL time.Duration,
	lockThreshold int64,
	lockTTL time.Duration,
) (*cacheport.RateLimitIncrementResult, error) {
	return r.incrementWithLock(ctx, r.key.LoginFailIP(ip), r.key.IPLock(ip), counterTTL, lockThreshold, lockTTL)
}

func (r *RateLimitRepository) GetLoginFailByUser(ctx context.Context, username string) (int64, error) {
	value, err := r.rdb.Get(ctx, r.key.LoginFailUser(username)).Result()
	if err == goredis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return parseInt64(value), nil
}

func (r *RateLimitRepository) GetLoginFailByIP(ctx context.Context, ip string) (int64, error) {
	value, err := r.rdb.Get(ctx, r.key.LoginFailIP(ip)).Result()
	if err == goredis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return parseInt64(value), nil
}

func (r *RateLimitRepository) ResetLoginFailByUser(ctx context.Context, username string) error {
	return r.rdb.Del(ctx, r.key.LoginFailUser(username)).Err()
}

func (r *RateLimitRepository) ResetLoginFailByIP(ctx context.Context, ip string) error {
	return r.rdb.Del(ctx, r.key.LoginFailIP(ip)).Err()
}

func (r *RateLimitRepository) IncrementBlacklistByUser(
	ctx context.Context,
	username, userID string,
	lockThreshold int64,
) (*cacheport.RateLimitIncrementResult, error) {
	lockKey := ""
	if strings.TrimSpace(userID) != "" {
		lockKey = r.key.UserLock(strings.TrimSpace(userID))
	}
	return r.incrementWithLock(ctx, r.key.LoginBlacklistUser(username), lockKey, 0, lockThreshold, 0)
}

func (r *RateLimitRepository) ResetBlacklistByUser(ctx context.Context, username string) error {
	return r.rdb.Del(ctx, r.key.LoginBlacklistUser(username)).Err()
}

func (r *RateLimitRepository) SetUserLock(ctx context.Context, userID string, ttl time.Duration) error {
	return r.rdb.Set(ctx, r.key.UserLock(userID), "1", ttl).Err()
}

func (r *RateLimitRepository) IsUserLocked(ctx context.Context, userID string) (bool, error) {
	exists, err := r.rdb.Exists(ctx, r.key.UserLock(userID)).Result()
	return exists > 0, err
}

func (r *RateLimitRepository) ClearUserLock(ctx context.Context, userID string) error {
	return r.rdb.Del(ctx, r.key.UserLock(userID)).Err()
}

func (r *RateLimitRepository) IsIPLocked(ctx context.Context, ip string) (bool, error) {
	exists, err := r.rdb.Exists(ctx, r.key.IPLock(ip)).Result()
	return exists > 0, err
}

func (r *RateLimitRepository) ClearIPLock(ctx context.Context, ip string) error {
	return r.rdb.Del(ctx, r.key.IPLock(ip)).Err()
}

func (r *RateLimitRepository) incrementWithLock(
	ctx context.Context,
	counterKey, lockKey string,
	counterTTL time.Duration,
	lockThreshold int64,
	lockTTL time.Duration,
) (*cacheport.RateLimitIncrementResult, error) {
	cmd := runScript(
		ctx,
		r.scripts.incrementWithTTL,
		r.rdb,
		[]string{counterKey, lockKey},
		durationSeconds(counterTTL),
		lockThreshold,
		durationSeconds(lockTTL),
	)
	if err := cmd.Err(); err != nil {
		return nil, err
	}
	values, err := cmd.Int64Slice()
	if err != nil {
		return nil, err
	}
	if len(values) < 3 {
		return &cacheport.RateLimitIncrementResult{}, nil
	}
	return &cacheport.RateLimitIncrementResult{
		Count:  values[0],
		Locked: values[2] == 1,
	}, nil
}
