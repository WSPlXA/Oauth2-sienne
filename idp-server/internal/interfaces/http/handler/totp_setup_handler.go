package handler

import (
	"errors"
	"net/http"

	appmfa "idp-server/internal/application/mfa"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type TOTPSetupHandler struct {
	service appmfa.Manager
}

type totpSetupPageData struct {
	Secret          string
	ProvisioningURI string
	CSRFToken       string
	Error           string
	Success         bool
	AlreadyEnabled  bool
}

func NewTOTPSetupHandler(service appmfa.Manager) *TOTPSetupHandler {
	return &TOTPSetupHandler{service: service}
}

func (h *TOTPSetupHandler) Handle(c *gin.Context) {
	sessionID, _ := c.Cookie("idp_session")
	if c.Request.Method == http.MethodGet {
		result, err := h.service.BeginSetup(c.Request.Context(), sessionID)
		if err != nil {
			h.writeError(c, err, false)
			return
		}
		h.render(c, http.StatusOK, totpSetupPageData{
			Secret:          result.Secret,
			ProvisioningURI: result.ProvisioningURI,
			AlreadyEnabled:  result.AlreadyEnabled,
		})
		return
	}

	var req dto.TOTPSetupRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid totp setup request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		h.render(c, http.StatusForbidden, totpSetupPageData{Error: errInvalidCSRFToken.Error()})
		return
	}
	result, err := h.service.ConfirmSetup(c.Request.Context(), sessionID, req.Code)
	if err != nil {
		h.writeError(c, err, true)
		return
	}
	h.render(c, http.StatusOK, totpSetupPageData{
		Success: result.Enabled,
		Error:   "TOTP has been enabled.",
	})
}

func (h *TOTPSetupHandler) render(c *gin.Context, status int, data totpSetupPageData) {
	if token, err := ensureCSRFToken(c); err == nil {
		data.CSRFToken = token
	}
	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.TOTPSetupTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, gin.H{
		"secret":           data.Secret,
		"provisioning_uri": data.ProvisioningURI,
		"already_enabled":  data.AlreadyEnabled,
		"enabled":          data.Success,
		"csrf_token":       data.CSRFToken,
		"error":            data.Error,
	})
}

func (h *TOTPSetupHandler) writeError(c *gin.Context, err error, preserve bool) {
	status := http.StatusInternalServerError
	data := totpSetupPageData{}
	switch {
	case errors.Is(err, appmfa.ErrLoginRequired):
		c.Redirect(http.StatusFound, withReturnTo("/login", "/mfa/totp/setup"))
		return
	case errors.Is(err, appmfa.ErrAlreadyEnabled):
		status = http.StatusConflict
		data.AlreadyEnabled = true
		data.Error = err.Error()
	case errors.Is(err, appmfa.ErrEnrollmentExpired), errors.Is(err, appmfa.ErrInvalidTOTPCode):
		status = http.StatusBadRequest
		data.Error = err.Error()
	default:
		data.Error = "totp setup failed"
	}
	if preserve && status == http.StatusBadRequest {
		sessionID, _ := c.Cookie("idp_session")
		if result, beginErr := h.service.BeginSetup(c.Request.Context(), sessionID); beginErr == nil && result != nil {
			data.Secret = result.Secret
			data.ProvisioningURI = result.ProvisioningURI
			data.AlreadyEnabled = result.AlreadyEnabled
		}
	}
	h.render(c, status, data)
}
