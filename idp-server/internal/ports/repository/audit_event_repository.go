package repository

import (
	"context"
	"time"

	"idp-server/internal/domain/audit"
)

type ListAuditEventsInput struct {
	Limit     int
	Offset    int
	EventType string
	UserID    *int64
	Subject   string
	From      *time.Time
	To        *time.Time
}

type AuditEventRepository interface {
	Create(ctx context.Context, model *audit.Model) error
	List(ctx context.Context, input ListAuditEventsInput) ([]*audit.Model, error)
}
