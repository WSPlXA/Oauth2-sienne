package authorization

import "time"

type Model struct {
	ID                  int64
	Code                string
	ClientDBID          int64
	UserID              int64
	SessionDBID         *int64
	RedirectURI         string
	ScopesJSON          string
	StateValue          string
	NonceValue          string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
	CreatedAt           time.Time
}
