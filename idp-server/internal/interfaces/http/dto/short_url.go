package dto

import "time"

type CreateShortURLRequest struct {
	Code      string     `json:"code" form:"code"`
	TargetURL string     `json:"target_url" form:"target_url"`
	ExpiresAt *time.Time `json:"expires_at" form:"expires_at" time_format:"2006-01-02T15:04:05Z07:00"`
}
