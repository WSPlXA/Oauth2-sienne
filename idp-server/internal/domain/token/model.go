package token

import "time"

type Model struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
}

type AccessToken struct {
	ID           int64
	TokenValue   string
	TokenSHA256  string
	ClientID     int64
	UserID       *int64
	Subject      string
	AudienceJSON string
	ScopesJSON   string
	TokenType    string
	TokenFormat  string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	CreatedAt    time.Time
}

type RefreshToken struct {
	ID                int64
	TokenValue        string
	TokenSHA256       string
	ClientID          int64
	UserID            *int64
	Subject           string
	ScopesJSON        string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	ReplacedByTokenID *int64
	CreatedAt         time.Time
}
