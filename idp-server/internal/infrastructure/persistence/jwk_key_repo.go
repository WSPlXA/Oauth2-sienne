package persistence

import (
	"context"
	"database/sql"
	"time"
)

type JWKKeyRecord struct {
	ID            int64
	KID           string
	KTY           string
	Alg           string
	UseType       string
	PublicJWKJSON string
	PrivateKeyRef string
	IsActive      bool
	CreatedAt     time.Time
	RotatesAt     *time.Time
	DeactivatedAt *time.Time
}

type JWKKeyRepository struct {
	db *sql.DB
}

func NewJWKKeyRepository(db *sql.DB) *JWKKeyRepository {
	return &JWKKeyRepository{db: db}
}

func (r *JWKKeyRepository) ListCurrent(ctx context.Context) ([]JWKKeyRecord, error) {
	const query = `
SELECT
    id,
    kid,
    kty,
    alg,
    use_type,
    public_jwk_json,
    private_key_ref,
    is_active,
    created_at,
    rotates_at,
    deactivated_at
FROM jwk_keys
WHERE deactivated_at IS NULL OR deactivated_at > UTC_TIMESTAMP()
ORDER BY is_active DESC, created_at DESC, id DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []JWKKeyRecord
	for rows.Next() {
		var record JWKKeyRecord
		var privateKeyRef sql.NullString
		var rotatesAt sql.NullTime
		var deactivatedAt sql.NullTime
		if err := rows.Scan(
			&record.ID,
			&record.KID,
			&record.KTY,
			&record.Alg,
			&record.UseType,
			&record.PublicJWKJSON,
			&privateKeyRef,
			&record.IsActive,
			&record.CreatedAt,
			&rotatesAt,
			&deactivatedAt,
		); err != nil {
			return nil, err
		}
		record.PrivateKeyRef = privateKeyRef.String
		if rotatesAt.Valid {
			value := rotatesAt.Time
			record.RotatesAt = &value
		}
		if deactivatedAt.Valid {
			value := deactivatedAt.Time
			record.DeactivatedAt = &value
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func (r *JWKKeyRepository) CreateActiveKey(ctx context.Context, record JWKKeyRecord, retiresExistingAt time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	const deactivateQuery = `
UPDATE jwk_keys
SET is_active = 0,
    deactivated_at = CASE
        WHEN deactivated_at IS NULL OR deactivated_at > ? THEN ?
        ELSE deactivated_at
    END
WHERE is_active = 1`

	if _, err := tx.ExecContext(ctx, deactivateQuery, retiresExistingAt, retiresExistingAt); err != nil {
		return err
	}

	const insertQuery = `
INSERT INTO jwk_keys (
    kid,
    kty,
    alg,
    use_type,
    public_jwk_json,
    private_key_ref,
    is_active,
    created_at,
    rotates_at,
    deactivated_at
) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, NULL)`

	_, err = tx.ExecContext(
		ctx,
		insertQuery,
		record.KID,
		record.KTY,
		record.Alg,
		record.UseType,
		record.PublicJWKJSON,
		nullString(record.PrivateKeyRef),
		record.CreatedAt,
		nullTime(record.RotatesAt),
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}
