package handler

import (
	"errors"
	"net/http"
	"strings"

	"idp-server/internal/application/oidc"
	"idp-server/internal/interfaces/http/middleware"

	"github.com/gin-gonic/gin"
)

type UserInfoHandler struct {
	oidcService oidc.UserInfoProvider
}

func NewUserInfoHandler(oidcService oidc.UserInfoProvider) *UserInfoHandler {
	return &UserInfoHandler{oidcService: oidcService}
}

func (h *UserInfoHandler) Handle(c *gin.Context) {
	token := tokenFromContextOrHeader(c)
	result, err := h.oidcService.GetUserInfo(c.Request.Context(), oidc.UserInfoInput{
		AccessToken: token,
	})
	if err != nil {
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, oidc.ErrUserNotFound):
			status = http.StatusNotFound
		case errors.Is(err, oidc.ErrInvalidAccessToken):
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
		}

		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

func extractBearerToken(authorizationHeader string) string {
	if !strings.HasPrefix(authorizationHeader, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authorizationHeader, "Bearer "))
}

func tokenFromContextOrHeader(c *gin.Context) string {
	if value, ok := c.Get(middleware.ContextAccessToken); ok {
		if token, ok := value.(string); ok && token != "" {
			return token
		}
	}

	return extractBearerToken(c.GetHeader("Authorization"))
}
