package totp

import "time"

type Model struct {
	ID        int64
	UserID    int64
	Secret    string
	EnabledAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}
