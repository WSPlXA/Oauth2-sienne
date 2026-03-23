package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	authorizationdomain "idp-server/internal/domain/authorization"
)

type AuthorizationCodeRepository struct {
	db *sql.DB
}

func NewAuthorizationCodeRepository(db *sql.DB) *AuthorizationCodeRepository {
	return &AuthorizationCodeRepository{db: db}
}

func (r *AuthorizationCodeRepository) Create(ctx context.Context, model *authorizationdomain.Model) error {
	const query = `
INSERT INTO oauth_authorization_codes (
    code,
    client_id,
    user_id,
    session_id,
    redirect_uri,
    scopes_json,
    state_value,
    nonce_value,
    code_challenge,
    code_challenge_method,
    expires_at,
    consumed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(
		ctx,
		query,
		model.Code,
		model.ClientDBID,
		model.UserID,
		nullInt64(model.SessionDBID),
		model.RedirectURI,
		model.ScopesJSON,
		nullString(model.StateValue),
		nullString(model.NonceValue),
		nullString(model.CodeChallenge),
		nullString(model.CodeChallengeMethod),
		model.ExpiresAt,
		nullTime(model.ConsumedAt),
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err == nil {
		model.ID = id
	}
	return nil
}

func (r *AuthorizationCodeRepository) ConsumeByCode(ctx context.Context, code string, consumedAt time.Time) (*authorizationdomain.Model, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	const selectQuery = `
SELECT
    id,
    code,
    client_id,
    user_id,
    session_id,
    redirect_uri,
    scopes_json,
    state_value,
    nonce_value,
    code_challenge,
    code_challenge_method,
    expires_at,
    consumed_at,
    created_at
FROM oauth_authorization_codes
WHERE code = ?
FOR UPDATE`

	row := tx.QueryRowContext(ctx, selectQuery, code)
	model, err := scanAuthorizationCode(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if model.ConsumedAt != nil || !model.ExpiresAt.After(consumedAt) {
		return nil, nil
	}

	const updateQuery = `
UPDATE oauth_authorization_codes
SET consumed_at = ?
WHERE id = ?
  AND consumed_at IS NULL`

	result, err := tx.ExecContext(ctx, updateQuery, consumedAt, model.ID)
	if err != nil {
		return nil, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		return nil, nil
	}

	model.ConsumedAt = &consumedAt
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return model, nil
}

func scanAuthorizationCode(row scanner) (*authorizationdomain.Model, error) {
	var model authorizationdomain.Model
	var sessionID sql.NullInt64
	var stateValue sql.NullString
	var nonceValue sql.NullString
	var codeChallenge sql.NullString
	var codeChallengeMethod sql.NullString
	var consumedAt sql.NullTime

	err := row.Scan(
		&model.ID,
		&model.Code,
		&model.ClientDBID,
		&model.UserID,
		&sessionID,
		&model.RedirectURI,
		&model.ScopesJSON,
		&stateValue,
		&nonceValue,
		&codeChallenge,
		&codeChallengeMethod,
		&model.ExpiresAt,
		&consumedAt,
		&model.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if sessionID.Valid {
		value := sessionID.Int64
		model.SessionDBID = &value
	}
	model.StateValue = stateValue.String
	model.NonceValue = nonceValue.String
	model.CodeChallenge = codeChallenge.String
	model.CodeChallengeMethod = codeChallengeMethod.String
	if consumedAt.Valid {
		value := consumedAt.Time
		model.ConsumedAt = &value
	}

	return &model, nil
}
