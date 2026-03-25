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

type LoginHandler struct {
	authnService         authn.Authenticator
	federatedOIDCEnabled bool
}

type loginPageData struct {
	Username             string
	ReturnTo             string
	Error                string
	Success              bool
	FederatedOIDCEnabled bool
}

func NewLoginHandler(authnService authn.Authenticator, federatedOIDCEnabled bool) *LoginHandler {
	return &LoginHandler{
		authnService:         authnService,
		federatedOIDCEnabled: federatedOIDCEnabled,
	}
}

func (h *LoginHandler) Handle(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		req := dto.LoginRequest{
			Method:      c.Query("method"),
			ReturnTo:    c.Query("return_to"),
			RedirectURI: c.Query("redirect_uri"),
			State:       c.Query("state"),
			Code:        c.Query("code"),
			Nonce:       c.Query("nonce"),
		}
		if shouldProcessLoginGET(req) {
			h.handleAuthenticate(c, req)
			return
		}

		if wantsHTML(c.GetHeader("Accept")) {
			h.renderLoginPage(c, http.StatusOK, loginPageData{
				ReturnTo:             c.Query("return_to"),
				FederatedOIDCEnabled: h.federatedOIDCEnabled,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"endpoint":                "login",
			"message":                 "submit username and password to login",
			"return_to":               c.Query("return_to"),
			"federated_oidc_enabled":  h.federatedOIDCEnabled,
			"federated_oidc_endpoint": "/login?method=federated_oidc",
		})
		return
	}

	var req dto.LoginRequest
	if err := c.ShouldBind(&req); err != nil {
		if wantsHTML(c.GetHeader("Accept")) {
			h.renderLoginPage(c, http.StatusBadRequest, loginPageData{
				Username:             c.PostForm("username"),
				ReturnTo:             c.PostForm("return_to"),
				Error:                "ユーザー名とパスワードを入力してください。",
				FederatedOIDCEnabled: h.federatedOIDCEnabled,
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid login request"})
		return
	}

	h.handleAuthenticate(c, req)
}

func (h *LoginHandler) handleAuthenticate(c *gin.Context, req dto.LoginRequest) {
	result, err := h.authnService.Authenticate(c.Request.Context(), authn.AuthenticateInput{
		Method:      req.Method,
		Username:    req.Username,
		Password:    req.Password,
		RedirectURI: req.RedirectURI,
		ReturnTo:    req.ReturnTo,
		State:       req.State,
		Code:        req.Code,
		Nonce:       req.Nonce,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
	})
	if err != nil {
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, authn.ErrUnsupportedMethod):
			status = http.StatusBadRequest
		case errors.Is(err, authn.ErrUserLocked):
			status = http.StatusLocked
		case errors.Is(err, authn.ErrUserDisabled):
			status = http.StatusForbidden
		case errors.Is(err, authn.ErrInvalidCredentials):
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
		}

		if wantsHTML(c.GetHeader("Accept")) {
			h.renderLoginPage(c, status, loginPageData{
				Username:             req.Username,
				ReturnTo:             req.ReturnTo,
				Error:                localizeLoginError(err),
				FederatedOIDCEnabled: h.federatedOIDCEnabled,
			})
			return
		}

		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	if result != nil && result.SessionID == "" && result.RedirectURI != "" {
		c.Redirect(http.StatusFound, result.RedirectURI)
		return
	}

	maxAge := int(time.Until(result.ExpiresAt).Seconds())
	c.SetCookie("idp_session", result.SessionID, maxAge, "/", "", false, true)
	redirectURI := req.ReturnTo
	if redirectURI == "" {
		redirectURI = result.RedirectURI
	}
	if redirectURI != "" {
		c.Redirect(http.StatusFound, redirectURI)
		return
	}
	if wantsHTML(c.GetHeader("Accept")) {
		h.renderLoginPage(c, http.StatusOK, loginPageData{
			Username:             req.Username,
			Success:              true,
			FederatedOIDCEnabled: h.federatedOIDCEnabled,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"session_id": result.SessionID,
		"user_id":    result.UserID,
		"subject":    result.Subject,
		"expires_at": result.ExpiresAt,
	})
}

func shouldProcessLoginGET(req dto.LoginRequest) bool {
	if req.Method == string(authnMethodFederatedOIDC) {
		return true
	}
	return req.Code != "" || req.State != ""
}

const authnMethodFederatedOIDC = "federated_oidc"

func localizeLoginError(err error) string {
	switch {
	case errors.Is(err, authn.ErrInvalidCredentials):
		return "ユーザー名またはパスワードが正しくありません。"
	case errors.Is(err, authn.ErrUserLocked):
		return "アカウントはロックされています。"
	case errors.Is(err, authn.ErrUserDisabled):
		return "アカウントは無効化されています。"
	case errors.Is(err, authn.ErrUnsupportedMethod):
		return "この認証方式は現在利用できません。"
	default:
		return "ログイン処理に失敗しました。"
	}
}

func (h *LoginHandler) renderLoginPage(c *gin.Context, status int, data loginPageData) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	_ = resource.LoginPageTemplate.Execute(c.Writer, data)
}
