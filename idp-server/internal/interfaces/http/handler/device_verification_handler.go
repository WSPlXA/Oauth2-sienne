package handler

import (
	"errors"
	"net/http"
	"net/url"

	appdevice "idp-server/internal/application/device"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type DeviceVerificationHandler struct {
	verifier appdevice.Verifier
}

type devicePageData struct {
	UserCode   string
	ClientID   string
	ClientName string
	Scopes     []string
	CSRFToken  string
	Error      string
	Success    bool
}

func NewDeviceVerificationHandler(verifier appdevice.Verifier) *DeviceVerificationHandler {
	return &DeviceVerificationHandler{verifier: verifier}
}

func (h *DeviceVerificationHandler) Handle(c *gin.Context) {
	sessionID, _ := c.Cookie("idp_session")

	if c.Request.Method == http.MethodGet {
		userCode := c.Query("user_code")
		if userCode == "" {
			h.renderPage(c, http.StatusOK, devicePageData{})
			return
		}
		result, err := h.verifier.Prepare(c.Request.Context(), appdevice.PrepareInput{
			SessionID: sessionID,
			UserCode:  userCode,
		})
		if err != nil {
			h.writeError(c, err, userCode)
			return
		}
		h.renderPage(c, http.StatusOK, devicePageData{
			UserCode:   result.UserCode,
			ClientID:   result.ClientID,
			ClientName: result.ClientName,
			Scopes:     result.Scopes,
		})
		return
	}

	var req dto.DeviceVerifyRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid verification request"})
		return
	}
	if req.Action == "" {
		c.Redirect(http.StatusFound, "/device?user_code="+url.QueryEscape(req.UserCode))
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		h.renderPage(c, http.StatusForbidden, devicePageData{
			UserCode: req.UserCode,
			Error:    "リクエストの整合性検証に失敗しました。",
		})
		return
	}

	result, err := h.verifier.Decide(c.Request.Context(), appdevice.DecideInput{
		SessionID: sessionID,
		UserCode:  req.UserCode,
		Action:    req.Action,
	})
	if err != nil {
		h.writeError(c, err, req.UserCode)
		return
	}
	h.renderPage(c, http.StatusOK, devicePageData{
		UserCode: req.UserCode,
		Success:  true,
		Error:    successMessage(result.Approved),
	})
}

func (h *DeviceVerificationHandler) renderPage(c *gin.Context, status int, data devicePageData) {
	csrfToken, err := ensureCSRFToken(c)
	if err == nil {
		data.CSRFToken = csrfToken
	}
	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.DevicePageTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, data)
}

func (h *DeviceVerificationHandler) writeError(c *gin.Context, err error, userCode string) {
	switch {
	case errors.Is(err, appdevice.ErrLoginRequired):
		c.Redirect(http.StatusFound, withReturnTo("/login", "/device?user_code="+url.QueryEscape(userCode)))
	case errors.Is(err, appdevice.ErrInvalidUserCode), errors.Is(err, appdevice.ErrInvalidAction):
		h.renderPage(c, http.StatusBadRequest, devicePageData{
			UserCode: userCode,
			Error:    err.Error(),
		})
	default:
		h.renderPage(c, http.StatusInternalServerError, devicePageData{
			UserCode: userCode,
			Error:    "device verification failed",
		})
	}
}

func successMessage(approved bool) string {
	if approved {
		return "デバイスの認証を承認しました。元の画面に戻って続行してください。"
	}
	return "デバイスの認証を拒否しました。"
}
