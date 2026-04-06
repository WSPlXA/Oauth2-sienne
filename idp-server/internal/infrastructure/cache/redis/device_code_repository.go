package redis

import (
	"context"
	"time"

	cacheport "idp-server/internal/ports/cache"

	goredis "github.com/redis/go-redis/v9"
)

type DeviceCodeRepository struct {
	rdb *goredis.Client
	key *KeyBuilder
}

func NewDeviceCodeRepository(rdb *goredis.Client, key *KeyBuilder) *DeviceCodeRepository {
	return &DeviceCodeRepository{rdb: rdb, key: key}
}

func (r *DeviceCodeRepository) Save(ctx context.Context, entry cacheport.DeviceCodeEntry, ttl time.Duration) error {
	deviceKey := r.key.DeviceCode(entry.DeviceCode)
	userKey := r.key.DeviceUserCode(entry.UserCode)

	pipe := r.rdb.TxPipeline()
	pipe.HSet(ctx, deviceKey, map[string]any{
		"device_code":    entry.DeviceCode,
		"user_code":      entry.UserCode,
		"client_id":      entry.ClientID,
		"client_name":    entry.ClientName,
		"scopes_json":    entry.ScopesJSON,
		"status":         entry.Status,
		"user_id":        entry.UserID,
		"subject":        entry.Subject,
		"expires_at":     formatTime(entry.ExpiresAt),
		"approved_at":    zeroAwareTime(entry.ApprovedAt),
		"denied_at":      zeroAwareTime(entry.DeniedAt),
		"consumed_at":    zeroAwareTime(entry.ConsumedAt),
		"last_polled_at": zeroAwareTime(entry.LastPolledAt),
		"interval":       entry.Interval,
	})
	pipe.Set(ctx, userKey, entry.DeviceCode, ttl)
	pipe.Expire(ctx, deviceKey, ttl)
	pipe.Expire(ctx, userKey, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *DeviceCodeRepository) GetByDeviceCode(ctx context.Context, deviceCode string) (*cacheport.DeviceCodeEntry, error) {
	values, err := r.rdb.HGetAll(ctx, r.key.DeviceCode(deviceCode)).Result()
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}
	return mapDeviceCodeEntry(values), nil
}

func (r *DeviceCodeRepository) GetByUserCode(ctx context.Context, userCode string) (*cacheport.DeviceCodeEntry, error) {
	deviceCode, err := r.rdb.Get(ctx, r.key.DeviceUserCode(userCode)).Result()
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r.GetByDeviceCode(ctx, deviceCode)
}

func (r *DeviceCodeRepository) Approve(ctx context.Context, userCode string, userID string, subject string, approvedAt time.Time) error {
	entry, err := r.GetByUserCode(ctx, userCode)
	if err != nil || entry == nil {
		return err
	}
	deviceKey := r.key.DeviceCode(entry.DeviceCode)
	return r.rdb.HSet(ctx, deviceKey, map[string]any{
		"status":      "approved",
		"user_id":     userID,
		"subject":     subject,
		"approved_at": formatTime(approvedAt),
	}).Err()
}

func (r *DeviceCodeRepository) Deny(ctx context.Context, userCode string, deniedAt time.Time) error {
	entry, err := r.GetByUserCode(ctx, userCode)
	if err != nil || entry == nil {
		return err
	}
	return r.rdb.HSet(ctx, r.key.DeviceCode(entry.DeviceCode), map[string]any{
		"status":    "denied",
		"denied_at": formatTime(deniedAt),
	}).Err()
}

func (r *DeviceCodeRepository) MarkConsumed(ctx context.Context, deviceCode string, consumedAt time.Time) error {
	return r.rdb.HSet(ctx, r.key.DeviceCode(deviceCode), map[string]any{
		"status":      "consumed",
		"consumed_at": formatTime(consumedAt),
	}).Err()
}

func (r *DeviceCodeRepository) TouchPoll(ctx context.Context, deviceCode string, polledAt time.Time, minInterval time.Duration) (bool, error) {
	key := r.key.DeviceCode(deviceCode)
	allowed := false
	err := r.rdb.Watch(ctx, func(tx *goredis.Tx) error {
		values, err := tx.HGetAll(ctx, key).Result()
		if err != nil {
			return err
		}
		if len(values) == 0 {
			allowed = false
			return nil
		}
		last := parseTime(values["last_polled_at"])
		if !last.IsZero() && polledAt.Before(last.Add(minInterval)) {
			allowed = false
			return nil
		}
		_, err = tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
			pipe.HSet(ctx, key, "last_polled_at", formatTime(polledAt))
			return nil
		})
		if err != nil {
			return err
		}
		allowed = true
		return nil
	}, key)
	return allowed, err
}

func mapDeviceCodeEntry(values map[string]string) *cacheport.DeviceCodeEntry {
	return &cacheport.DeviceCodeEntry{
		DeviceCode:   values["device_code"],
		UserCode:     values["user_code"],
		ClientID:     values["client_id"],
		ClientName:   values["client_name"],
		ScopesJSON:   values["scopes_json"],
		Status:       values["status"],
		UserID:       values["user_id"],
		Subject:      values["subject"],
		ExpiresAt:    parseTime(values["expires_at"]),
		ApprovedAt:   parseTime(values["approved_at"]),
		DeniedAt:     parseTime(values["denied_at"]),
		ConsumedAt:   parseTime(values["consumed_at"]),
		LastPolledAt: parseTime(values["last_polled_at"]),
		Interval:     parseInt64(values["interval"]),
	}
}

func zeroAwareTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return formatTime(value)
}
