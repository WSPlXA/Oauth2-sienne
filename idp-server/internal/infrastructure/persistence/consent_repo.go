package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

type ConsentRepository struct {
	db *sql.DB
}

func NewConsentRepository(db *sql.DB) *ConsentRepository {
	return &ConsentRepository{db: db}
}

func (r *ConsentRepository) HasActiveConsent(ctx context.Context, userID, clientID int64, scopes []string) (bool, error) {
	const query = `
SELECT scopes_json
FROM oauth_consents
WHERE user_id = ?
  AND client_id = ?
  AND revoked_at IS NULL
LIMIT 1`

	var scopesJSON string
	err := r.db.QueryRowContext(ctx, query, userID, clientID).Scan(&scopesJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	var grantedScopes []string
	if err := json.Unmarshal([]byte(scopesJSON), &grantedScopes); err != nil {
		return false, err
	}

	granted := make(map[string]struct{}, len(grantedScopes))
	for _, scope := range grantedScopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		granted[scope] = struct{}{}
	}

	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := granted[scope]; !ok {
			return false, nil
		}
	}

	return true, nil
}

func (r *ConsentRepository) UpsertActiveConsent(ctx context.Context, userID, clientID int64, scopes []string, grantedAt time.Time) error {
	const selectQuery = `
SELECT scopes_json
FROM oauth_consents
WHERE user_id = ?
  AND client_id = ?
LIMIT 1`

	var existingJSON string
	err := r.db.QueryRowContext(ctx, selectQuery, userID, clientID).Scan(&existingJSON)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	scopeSet := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		scopeSet[scope] = struct{}{}
	}

	if err != sql.ErrNoRows && strings.TrimSpace(existingJSON) != "" {
		var existingScopes []string
		if unmarshalErr := json.Unmarshal([]byte(existingJSON), &existingScopes); unmarshalErr != nil {
			return unmarshalErr
		}
		for _, scope := range existingScopes {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				continue
			}
			scopeSet[scope] = struct{}{}
		}
	}

	mergedScopes := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		mergedScopes = append(mergedScopes, scope)
	}

	scopesJSON, err := json.Marshal(mergedScopes)
	if err != nil {
		return err
	}

	const query = `
INSERT INTO oauth_consents (
    user_id,
    client_id,
    scopes_json,
    granted_at,
    revoked_at
) VALUES (?, ?, ?, ?, NULL)
ON DUPLICATE KEY UPDATE
    scopes_json = VALUES(scopes_json),
    granted_at = VALUES(granted_at),
    revoked_at = NULL`

	_, err = r.db.ExecContext(ctx, query, userID, clientID, string(scopesJSON), grantedAt)
	return err
}
