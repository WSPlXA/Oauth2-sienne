package handler

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	auditdomain "idp-server/internal/domain/audit"
	"idp-server/internal/ports/repository"

	"github.com/gin-gonic/gin"
)

func recordLoginSuccessAuditEvent(ctx context.Context, repo repository.AuditEventRepository, c *gin.Context, resultUserID int64, subject, roleCode, method, redirectURI string) {
	if repo == nil || c == nil || resultUserID <= 0 {
		return
	}
	metadata := map[string]any{
		"method":       strings.TrimSpace(method),
		"role_code":    strings.TrimSpace(roleCode),
		"redirect_uri": strings.TrimSpace(redirectURI),
	}
	metadataJSON := ""
	if data, err := json.Marshal(metadata); err == nil {
		metadataJSON = string(data)
	}

	model := &auditdomain.Model{
		EventType:    "auth.login.succeeded",
		UserID:       ptrInt64(resultUserID),
		Subject:      strings.TrimSpace(subject),
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		MetadataJSON: metadataJSON,
	}
	if err := repo.Create(ctx, model); err != nil {
		log.Printf("audit_event create failed event_type=%s user_id=%d err=%v", model.EventType, resultUserID, err)
	}
}
