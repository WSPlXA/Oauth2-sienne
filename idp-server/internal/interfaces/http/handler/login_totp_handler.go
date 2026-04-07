package handler

import (
	"errors"
	"net/http"
	"time"

	"idp-server/internal/application/authn"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

const mfaChallengeCookieName = "idp_mfa_challenge"

type LoginTOTPHandler struct {
	authnService authn.Authenticator
}

type loginTOTPPageData struct {
	CSRFToken string
	Error     string
}

func NewLoginTOTPHandler(authnService authn.Authenticator) *LoginTOTPHandler {
	return &LoginTOTPHandler{authnService: authnService}
}

func (h *LoginTOTPHandler) Handle(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		h.render(c, http.StatusOK, loginTOTPPageData{})
		return
	}
	var req dto.LoginTOTPRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid totp login request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		h.render(c, http.StatusForbidden, loginTOTPPageData{Error: errInvalidCSRFToken.Error()})
		return
	}
	challengeID, _ := c.Cookie(mfaChallengeCookieName)
	result, err := h.authnService.VerifyTOTP(c.Request.Context(), authn.VerifyTOTPInput{
		ChallengeID: challengeID,
		Code:        req.Code,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
	})
	if err != nil {
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, authn.ErrMFAChallengeExpired):
			status = http.StatusUnauthorized
			c.SetCookie(mfaChallengeCookieName, "", -1, "/", "", false, true)
		case errors.Is(err, authn.ErrInvalidTOTPCode), errors.Is(err, authn.ErrTOTPCodeReused):
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
		}
		h.render(c, status, loginTOTPPageData{Error: err.Error()})
		return
	}
	c.SetCookie(mfaChallengeCookieName, "", -1, "/", "", false, true)
	maxAge := int(time.Until(result.ExpiresAt).Seconds())
	c.SetCookie("idp_session", result.SessionID, maxAge, "/", "", false, true)
	redirectURI := result.ReturnTo
	if redirectURI == "" {
		redirectURI = result.RedirectURI
	}
	if redirectURI != "" {
		c.Redirect(http.StatusFound, redirectURI)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"session_id": result.SessionID,
		"user_id":    result.UserID,
		"subject":    result.Subject,
		"expires_at": result.ExpiresAt,
	})
}

func (h *LoginTOTPHandler) render(c *gin.Context, status int, data loginTOTPPageData) {
	if token, err := ensureCSRFToken(c); err == nil {
		data.CSRFToken = token
	}
	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.LoginTOTPTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, gin.H{"csrf_token": data.CSRFToken, "error": data.Error})
}
