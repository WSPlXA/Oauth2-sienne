package session

import "time"

type Model struct {
	ID              int64
	SessionID       string
	UserID          int64
	Subject         string
	ACR             string
	AMRJSON         string
	IPAddress       string
	UserAgent       string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	LoggedOutAt     *time.Time
	CreatedAt       time.Time
}
