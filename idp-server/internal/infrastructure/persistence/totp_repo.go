package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	totpdomain "idp-server/internal/domain/totp"
)

type TOTPRepository struct {
	db *sql.DB
}

func NewTOTPRepository(db *sql.DB) *TOTPRepository {
	return &TOTPRepository{db: db}
}

func (r *TOTPRepository) FindByUserID(ctx context.Context, userID int64) (*totpdomain.Model, error) {
	const query = `
SELECT id, user_id, secret, enabled_at, created_at, updated_at
FROM user_totp_credentials
WHERE user_id = ?
LIMIT 1`

	var model totpdomain.Model
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&model.ID,
		&model.UserID,
		&model.Secret,
		&model.EnabledAt,
		&model.CreatedAt,
		&model.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &model, nil
}

func (r *TOTPRepository) Upsert(ctx context.Context, model *totpdomain.Model) error {
	const query = `
INSERT INTO user_totp_credentials (user_id, secret, enabled_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    secret = VALUES(secret),
    enabled_at = VALUES(enabled_at),
    updated_at = VALUES(updated_at)`

	now := time.Now().UTC()
	if model.CreatedAt.IsZero() {
		model.CreatedAt = now
	}
	if model.UpdatedAt.IsZero() {
		model.UpdatedAt = now
	}
	if model.EnabledAt.IsZero() {
		model.EnabledAt = now
	}
	_, err := r.db.ExecContext(ctx, query, model.UserID, model.Secret, model.EnabledAt, model.CreatedAt, model.UpdatedAt)
	return err
}

func (r *TOTPRepository) DeleteByUserID(ctx context.Context, userID int64) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM user_totp_credentials WHERE user_id = ?`, userID)
	return err
}
