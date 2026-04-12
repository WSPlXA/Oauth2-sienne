package cache

import (
	"context"
	"time"
)

// RateLimitRepository 定义登录失败计数和账户锁定相关的缓存接口。
// 这些状态属于高频、短生命周期数据，适合放在 Redis 等缓存中实现。
type RateLimitRepository interface {
	IncrementLoginFailByUser(ctx context.Context, username string, ttl time.Duration) (int64, error)
	IncrementLoginFailByIP(ctx context.Context, ip string, ttl time.Duration) (int64, error)

	GetLoginFailByUser(ctx context.Context, username string) (int64, error)
	GetLoginFailByIP(ctx context.Context, ip string) (int64, error)
	ResetLoginFailByUser(ctx context.Context, username string) error
	ResetLoginFailByIP(ctx context.Context, ip string) error

	SetUserLock(ctx context.Context, userID string, ttl time.Duration) error
	IsUserLocked(ctx context.Context, userID string) (bool, error)
	ClearUserLock(ctx context.Context, userID string) error
}
