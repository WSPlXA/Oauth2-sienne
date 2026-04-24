package shorturl

import "time"

type Link struct {
	ID           int64
	Code         string
	TargetURL    string
	ClickCount   int64
	ExpiresAt    *time.Time
	LastAccessAt *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
