package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	httpmiddleware "idp-server/internal/interfaces/http/middleware"
	"idp-server/internal/ports/repository"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type AuditConsoleHandler struct {
	audits repository.AuditEventRepository
	users  repository.UserRepository
}

type auditConsolePageData struct {
	Username            string
	RoleCode            string
	PrivilegeMask       uint32
	FilterEventType     string
	FilterActorUsername string
	FilterSubject       string
	Limit               int
	Rows                []auditConsoleRow
	LoadedCount         int
	LoginCount          int
	OperationCount      int
	Error               string
}

type auditConsoleRow struct {
	ID            int64
	CreatedAt     string
	EventType     string
	ActorUserID   int64
	ActorUsername string
	Subject       string
	IPAddress     string
	UserAgent     string
	Metadata      string
}

func NewAuditConsoleHandler(audits repository.AuditEventRepository, users repository.UserRepository) *AuditConsoleHandler {
	return &AuditConsoleHandler{
		audits: audits,
		users:  users,
	}
}

func (h *AuditConsoleHandler) Handle(c *gin.Context) {
	data := auditConsolePageData{
		Limit: defaultAuditListLimit,
	}
	if adminUser := httpmiddleware.CurrentAdminUser(c); adminUser != nil {
		data.Username = adminUser.Username
		data.RoleCode = adminUser.RoleCode
		data.PrivilegeMask = adminUser.PrivilegeMask
	}
	if h.audits == nil {
		h.write(c, http.StatusServiceUnavailable, auditConsolePageData{
			Error: "audit repository unavailable",
		})
		return
	}

	data.FilterEventType = strings.TrimSpace(c.Query("event_type"))
	data.FilterActorUsername = strings.TrimSpace(c.Query("actor_username"))
	data.FilterSubject = strings.TrimSpace(c.Query("subject"))
	if parsedLimit := parseAuditLimit(c.Query("limit")); parsedLimit > 0 {
		data.Limit = parsedLimit
	}

	var filterUserID *int64
	if data.FilterActorUsername != "" {
		if h.users == nil {
			data.Error = "user lookup service unavailable"
			h.write(c, http.StatusOK, data)
			return
		}
		userModel, err := h.users.FindByUsername(c.Request.Context(), data.FilterActorUsername)
		if err != nil {
			data.Error = "failed to resolve actor username: " + err.Error()
			h.write(c, http.StatusOK, data)
			return
		}
		if userModel == nil {
			data.Error = "actor username not found: " + data.FilterActorUsername
			h.write(c, http.StatusOK, data)
			return
		}
		filterUserID = ptrInt64(userModel.ID)
	}

	events, err := h.audits.List(c.Request.Context(), repository.ListAuditEventsInput{
		Limit:     data.Limit,
		EventType: data.FilterEventType,
		UserID:    filterUserID,
		Subject:   data.FilterSubject,
	})
	if err != nil {
		data.Error = "failed to load audit events: " + err.Error()
		h.write(c, http.StatusInternalServerError, data)
		return
	}

	usernameCache := map[int64]string{}
	resolveUsername := func(userID int64) string {
		if userID <= 0 {
			return "-"
		}
		if value, ok := usernameCache[userID]; ok {
			return value
		}
		if h.users == nil {
			usernameCache[userID] = "-"
			return "-"
		}
		userModel, err := h.users.FindByID(c.Request.Context(), userID)
		if err != nil || userModel == nil {
			usernameCache[userID] = "-"
			return "-"
		}
		usernameCache[userID] = strings.TrimSpace(userModel.Username)
		if usernameCache[userID] == "" {
			usernameCache[userID] = "-"
		}
		return usernameCache[userID]
	}

	rows := make([]auditConsoleRow, 0, len(events))
	loginCount := 0
	operationCount := 0
	for _, event := range events {
		if event == nil {
			continue
		}
		row := auditConsoleRow{
			ID:        event.ID,
			CreatedAt: event.CreatedAt.UTC().Format(time.RFC3339),
			EventType: strings.TrimSpace(event.EventType),
			Subject:   strings.TrimSpace(event.Subject),
			IPAddress: strings.TrimSpace(event.IPAddress),
			UserAgent: strings.TrimSpace(event.UserAgent),
			Metadata:  normalizeAuditMetadata(event.MetadataJSON),
		}
		if event.UserID != nil && *event.UserID > 0 {
			row.ActorUserID = *event.UserID
			row.ActorUsername = resolveUsername(*event.UserID)
		} else {
			row.ActorUsername = "-"
		}

		if strings.HasPrefix(row.EventType, "auth.login.") {
			loginCount++
		}
		if strings.Contains(row.EventType, ".admin") || strings.HasPrefix(row.EventType, "rbac.") || strings.HasPrefix(row.EventType, "oauth.") || strings.HasPrefix(row.EventType, "key.") {
			operationCount++
		}
		rows = append(rows, row)
	}

	data.Rows = rows
	data.LoadedCount = len(rows)
	data.LoginCount = loginCount
	data.OperationCount = operationCount
	h.write(c, http.StatusOK, data)
}

const (
	defaultAuditListLimit = 100
	maxAuditListLimit     = 500
)

func parseAuditLimit(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultAuditListLimit
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return defaultAuditListLimit
	}
	if value > maxAuditListLimit {
		return maxAuditListLimit
	}
	return value
}

func normalizeAuditMetadata(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "-"
	}
	var payload any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return raw
	}
	pretty, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return raw
	}
	return string(pretty)
}

func (h *AuditConsoleHandler) write(c *gin.Context, status int, data auditConsolePageData) {
	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.AuditConsoleTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, gin.H{
		"operator": gin.H{
			"username":       data.Username,
			"role_code":      data.RoleCode,
			"privilege_mask": data.PrivilegeMask,
		},
		"filters": gin.H{
			"event_type":     data.FilterEventType,
			"actor_username": data.FilterActorUsername,
			"subject":        data.FilterSubject,
			"limit":          data.Limit,
		},
		"summary": gin.H{
			"loaded_count":    data.LoadedCount,
			"login_count":     data.LoginCount,
			"operation_count": data.OperationCount,
		},
		"rows":          data.Rows,
		"error_message": data.Error,
	})
}
