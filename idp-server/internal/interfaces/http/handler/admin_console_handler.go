package handler

import (
	"net/http"

	apprbac "idp-server/internal/application/rbac"
	httpmiddleware "idp-server/internal/interfaces/http/middleware"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type AdminConsoleHandler struct {
	rbacService apprbac.Manager
}

type adminConsolePageData struct {
	Username      string
	RoleCode      string
	PrivilegeMask uint32
	TenantScope   string
	Roles         []apprbac.RoleView
	Usage         []apprbac.RoleUsageView
	Error         string
}

func NewAdminConsoleHandler(rbacService apprbac.Manager) *AdminConsoleHandler {
	return &AdminConsoleHandler{rbacService: rbacService}
}

func (h *AdminConsoleHandler) Handle(c *gin.Context) {
	if h.rbacService == nil {
		h.writeError(c, http.StatusServiceUnavailable, "rbac service unavailable", adminConsolePageData{})
		return
	}

	adminUser := httpmiddleware.CurrentAdminUser(c)
	data := adminConsolePageData{}
	if adminUser != nil {
		data.Username = adminUser.Username
		data.RoleCode = adminUser.RoleCode
		data.PrivilegeMask = adminUser.PrivilegeMask
		data.TenantScope = adminUser.TenantScope
	}

	rolesResult, err := h.rbacService.ListRoles(c.Request.Context())
	if err != nil {
		h.writeError(c, http.StatusInternalServerError, "failed to load roles", data)
		return
	}
	if rolesResult != nil {
		data.Roles = rolesResult.Roles
	}

	usageResult, err := h.rbacService.RoleUsage(c.Request.Context())
	if err != nil {
		h.writeError(c, http.StatusInternalServerError, "failed to load role usage", data)
		return
	}
	if usageResult != nil {
		data.Usage = usageResult.Roles
	}

	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(http.StatusOK)
		_ = resource.AdminConsoleTemplate.Execute(c.Writer, data)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"operator": gin.H{
			"username":       data.Username,
			"role_code":      data.RoleCode,
			"privilege_mask": data.PrivilegeMask,
			"tenant_scope":   data.TenantScope,
		},
		"roles":      data.Roles,
		"role_usage": data.Usage,
	})
}

func (h *AdminConsoleHandler) writeError(c *gin.Context, status int, message string, data adminConsolePageData) {
	if wantsHTML(c.GetHeader("Accept")) {
		data.Error = message
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.AdminConsoleTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, gin.H{"error": message})
}
