package redis

import (
	"context"
	"time"

	cacheport "idp-server/internal/ports/cache"

	goredis "github.com/redis/go-redis/v9"
)

type TokenCacheRepository struct {
	rdb     *goredis.Client
	key     *KeyBuilder
	scripts *scriptSet
}

func NewTokenCacheRepository(rdb *goredis.Client, key *KeyBuilder) *TokenCacheRepository {
	scripts, err := loadScripts()
	if err != nil {
		panic(err)
	}

	return &TokenCacheRepository{
		rdb:     rdb,
		key:     key,
		scripts: scripts,
	}
}

func (r *TokenCacheRepository) SaveAccessToken(ctx context.Context, entry cacheport.AccessTokenCacheEntry, ttl time.Duration) error {
	data := map[string]any{
		"client_id":     entry.ClientID,
		"user_id":       entry.UserID,
		"subject":       entry.Subject,
		"scopes_json":   entry.ScopesJSON,
		"aud_json":      entry.AudienceJSON,
		"token_type":    entry.TokenType,
		"token_format":  entry.TokenFormat,
		"issued_at":     formatTime(entry.IssuedAt),
		"expires_at":    formatTime(entry.ExpiresAt),
		"revoked":       "0",
	}
	pipe := r.rdb.TxPipeline()
	pipe.HSet(ctx, r.key.AccessToken(entry.TokenSHA256), data)
	pipe.Expire(ctx, r.key.AccessToken(entry.TokenSHA256), ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *TokenCacheRepository) GetAccessToken(ctx context.Context, tokenSHA256 string) (*cacheport.AccessTokenCacheEntry, error) {
	result, err := r.rdb.HGetAll(ctx, r.key.AccessToken(tokenSHA256)).Result()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, nil
	}
	return &cacheport.AccessTokenCacheEntry{
		TokenSHA256:  tokenSHA256,
		ClientID:     result["client_id"],
		UserID:       result["user_id"],
		Subject:      result["subject"],
		ScopesJSON:   result["scopes_json"],
		AudienceJSON: result["aud_json"],
		TokenType:    result["token_type"],
		TokenFormat:  result["token_format"],
		IssuedAt:     parseTime(result["issued_at"]),
		ExpiresAt:    parseTime(result["expires_at"]),
	}, nil
}

func (r *TokenCacheRepository) SaveRefreshToken(ctx context.Context, entry cacheport.RefreshTokenCacheEntry, ttl time.Duration) error {
	data := map[string]any{
		"client_id":    entry.ClientID,
		"user_id":      entry.UserID,
		"subject":      entry.Subject,
		"scopes_json":  entry.ScopesJSON,
		"issued_at":    formatTime(entry.IssuedAt),
		"expires_at":   formatTime(entry.ExpiresAt),
		"revoked":      "0",
		"rotated_to":   "",
	}
	pipe := r.rdb.TxPipeline()
	pipe.HSet(ctx, r.key.RefreshToken(entry.TokenSHA256), data)
	pipe.Expire(ctx, r.key.RefreshToken(entry.TokenSHA256), ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *TokenCacheRepository) GetRefreshToken(ctx context.Context, tokenSHA256 string) (*cacheport.RefreshTokenCacheEntry, error) {
	result, err := r.rdb.HGetAll(ctx, r.key.RefreshToken(tokenSHA256)).Result()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, nil
	}
	return &cacheport.RefreshTokenCacheEntry{
		TokenSHA256: tokenSHA256,
		ClientID:    result["client_id"],
		UserID:      result["user_id"],
		Subject:     result["subject"],
		ScopesJSON:  result["scopes_json"],
		IssuedAt:    parseTime(result["issued_at"]),
		ExpiresAt:   parseTime(result["expires_at"]),
	}, nil
}

func (r *TokenCacheRepository) RevokeAccessToken(ctx context.Context, tokenSHA256 string, ttl time.Duration) error {
	_, err := runScript(
		ctx,
		r.scripts.revokeToken,
		r.rdb,
		[]string{
			r.key.AccessToken(tokenSHA256),
			r.key.RevokedAccessToken(tokenSHA256),
			"",
		},
		durationSeconds(ttl),
	).Result()
	return err
}

func (r *TokenCacheRepository) RevokeRefreshToken(ctx context.Context, tokenSHA256 string, ttl time.Duration) error {
	_, err := runScript(
		ctx,
		r.scripts.revokeToken,
		r.rdb,
		[]string{
			r.key.RefreshToken(tokenSHA256),
			r.key.RevokedRefreshToken(tokenSHA256),
			"",
		},
		durationSeconds(ttl),
	).Result()
	return err
}

func (r *TokenCacheRepository) IsAccessTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error) {
	exists, err := r.rdb.Exists(ctx, r.key.RevokedAccessToken(tokenSHA256)).Result()
	return exists > 0, err
}

func (r *TokenCacheRepository) IsRefreshTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error) {
	exists, err := r.rdb.Exists(ctx, r.key.RevokedRefreshToken(tokenSHA256)).Result()
	return exists > 0, err
}

func (r *TokenCacheRepository) RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, newEntry cacheport.RefreshTokenCacheEntry, newTTL time.Duration, oldRevokeTTL time.Duration) error {
	_, err := runScript(
		ctx,
		r.scripts.rotateToken,
		r.rdb,
		[]string{
			r.key.RefreshToken(oldTokenSHA256),
			r.key.RefreshToken(newEntry.TokenSHA256),
			r.key.RevokedRefreshToken(oldTokenSHA256),
			"",
			"",
		},
		oldTokenSHA256,
		newEntry.TokenSHA256,
		newEntry.ClientID,
		newEntry.UserID,
		newEntry.Subject,
		newEntry.ScopesJSON,
		formatTime(newEntry.IssuedAt),
		formatTime(newEntry.ExpiresAt),
		durationSeconds(newTTL),
		durationSeconds(oldRevokeTTL),
	).Result()
	return err
}
