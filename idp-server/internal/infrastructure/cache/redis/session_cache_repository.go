package redis

import (
	"context"
	"time"

	cacheport "idp-server/internal/ports/cache"

	goredis "github.com/redis/go-redis/v9"
)

type SessionCacheRepository struct {
	rdb     *goredis.Client
	key     *KeyBuilder
	scripts *scriptSet
}

func NewSessionCacheRepository(rdb *goredis.Client, key *KeyBuilder) *SessionCacheRepository {
	scripts, err := loadScripts()
	if err != nil {
		panic(err)
	}

	return &SessionCacheRepository{
		rdb:     rdb,
		key:     key,
		scripts: scripts,
	}
}

func (r *SessionCacheRepository) Save(ctx context.Context, entry cacheport.SessionCacheEntry, ttl time.Duration) error {
	_, err := runScript(
		ctx,
		r.scripts.saveSession,
		r.rdb,
		[]string{
			r.key.Session(entry.SessionID),
			r.key.UserSessionIndex(entry.UserID),
		},
		entry.SessionID,
		entry.UserID,
		entry.Subject,
		entry.ACR,
		entry.AMRJSON,
		entry.IPAddress,
		entry.UserAgent,
		formatTime(entry.AuthenticatedAt),
		formatTime(entry.ExpiresAt),
		entry.Status,
		durationSeconds(ttl),
	).Result()
	return err
}

func (r *SessionCacheRepository) Get(ctx context.Context, sessionID string) (*cacheport.SessionCacheEntry, error) {
	key := r.key.Session(sessionID)

	res, err := r.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, nil
	}

	authenticatedAt, _ := time.Parse(time.RFC3339, res["authenticated_at"])
	expiresAt, _ := time.Parse(time.RFC3339, res["expires_at"])

	return &cacheport.SessionCacheEntry{
		SessionID:       sessionID,
		UserID:          res["user_id"],
		Subject:         res["subject"],
		ACR:             res["acr"],
		AMRJSON:         res["amr_json"],
		IPAddress:       res["ip"],
		UserAgent:       res["user_agent"],
		AuthenticatedAt: authenticatedAt.UTC(),
		ExpiresAt:       expiresAt.UTC(),
		Status:          res["status"],
	}, nil
}

func (r *SessionCacheRepository) Delete(ctx context.Context, sessionID string) error {
	entry, err := r.Get(ctx, sessionID)
	if err != nil || entry == nil {
		if err != nil {
			return err
		}
		return r.rdb.Del(ctx, r.key.Session(sessionID)).Err()
	}

	_, err = runScript(
		ctx,
		r.scripts.deleteSession,
		r.rdb,
		[]string{
			r.key.Session(sessionID),
			r.key.UserSessionIndex(entry.UserID),
		},
		sessionID,
	).Result()
	return err
}

func (r *SessionCacheRepository) AddUserSessionIndex(ctx context.Context, userID string, sessionID string, ttl time.Duration) error {
	key := r.key.UserSessionIndex(userID)

	pipe := r.rdb.TxPipeline()
	pipe.SAdd(ctx, key, sessionID)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *SessionCacheRepository) ListUserSessionIDs(ctx context.Context, userID string) ([]string, error) {
	return r.rdb.SMembers(ctx, r.key.UserSessionIndex(userID)).Result()
}

func (r *SessionCacheRepository) RemoveUserSessionIndex(ctx context.Context, userID string, sessionID string) error {
	return r.rdb.SRem(ctx, r.key.UserSessionIndex(userID), sessionID).Err()
}
