package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	appclientauth "idp-server/internal/application/clientauth"
	appdevice "idp-server/internal/application/device"
	"idp-server/internal/interfaces/http/dto"
	apptoken "idp-server/internal/application/token"

	"github.com/gin-gonic/gin"
)

type DeviceAuthorizeHandler struct {
	clientAuthenticator appclientauth.Authenticator
	starter             appdevice.Starter
}

func NewDeviceAuthorizeHandler(clientAuthenticator appclientauth.Authenticator, starter appdevice.Starter) *DeviceAuthorizeHandler {
	return &DeviceAuthorizeHandler{
		clientAuthenticator: clientAuthenticator,
		starter:             starter,
	}
}

func (h *DeviceAuthorizeHandler) Handle(c *gin.Context) {
	var req dto.DeviceAuthorizeRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid device authorization request"})
		return
	}
	if h.clientAuthenticator == nil || h.starter == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "device authorization is not configured"})
		return
	}

	clientAuth, err := h.clientAuthenticator.Authenticate(c.Request.Context(), appclientauth.AuthenticateInput{
		AuthorizationHeader: c.GetHeader("Authorization"),
		ClientID:            req.ClientID,
		ClientSecret:        req.ClientSecret,
	})
	if err != nil {
		status := http.StatusUnauthorized
		code := "invalid_client"
		if !errors.Is(err, apptoken.ErrInvalidClient) {
			status = http.StatusInternalServerError
			code = "server_error"
		}
		c.JSON(status, gin.H{"error": code})
		return
	}

	result, err := h.starter.Start(c.Request.Context(), appdevice.StartInput{
		ClientID: clientAuth.ClientID,
		Scopes:   req.ScopeList(),
	})
	if err != nil {
		switch {
		case errors.Is(err, appdevice.ErrInvalidClient):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		case errors.Is(err, appdevice.ErrInvalidScope):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		}
		return
	}

	verificationURI := deviceVerificationURI(c)
	c.JSON(http.StatusOK, gin.H{
		"device_code":               result.DeviceCode,
		"user_code":                 result.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + result.UserCode,
		"expires_in":                int64(time.Until(result.ExpiresAt).Seconds()),
		"interval":                  result.Interval,
	})
}

func deviceVerificationURI(c *gin.Context) string {
	scheme := "http"
	if proto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); proto != "" {
		scheme = proto
	} else if c.Request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host + "/device"
}
