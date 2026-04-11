package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"

	appclientauth "idp-server/internal/application/clientauth"
	apptoken "idp-server/internal/application/token"
	"idp-server/internal/interfaces/http/dto"
	pluginregistry "idp-server/internal/plugins/registry"
	pluginport "idp-server/internal/ports/plugin"
	pkgoauth2 "idp-server/pkg/oauth2"

	"github.com/gin-gonic/gin"
)

type TokenHandler struct {
	clientAuthenticator appclientauth.Authenticator
	grantRegistry       *pluginregistry.GrantRegistry
}

func NewTokenHandler(clientAuthenticator appclientauth.Authenticator, grantRegistry *pluginregistry.GrantRegistry) *TokenHandler {
	return &TokenHandler{
		clientAuthenticator: clientAuthenticator,
		grantRegistry:       grantRegistry,
	}
}

func (h *TokenHandler) Handle(c *gin.Context) {
	var req dto.TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, pkgoauth2.Error{
			Code:        "invalid_request",
			Description: "invalid token request",
		})
		return
	}

	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, pkgoauth2.Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
		return
	}

	if h.clientAuthenticator == nil || h.grantRegistry == nil {
		c.JSON(http.StatusInternalServerError, pkgoauth2.Error{
			Code:        "server_error",
			Description: "token handler is not configured",
		})
		return
	}

	clientAuth, err := h.clientAuthenticator.Authenticate(c.Request.Context(), appclientauth.AuthenticateInput{
		AuthorizationHeader: c.GetHeader("Authorization"),
		ClientID:            req.ClientID,
		ClientSecret:        req.ClientSecret,
	})
	if err != nil {
		log.Printf("client authentication failed grant_type=%s client_id=%s err=%v", req.GrantType, req.ClientID, err)
		status := http.StatusBadRequest
		oauthErr := pkgoauth2.Error{
			Code:        "invalid_client",
			Description: err.Error(),
		}

		switch {
		case errors.Is(err, apptoken.ErrInvalidClient):
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
			oauthErr.Code = "server_error"
			oauthErr.Description = "client authentication failed"
		}

		c.JSON(status, oauthErr)
		return
	}

	clientID := clientAuth.ClientID
	clientSecret := clientAuth.ClientSecret
	grantType := pkgoauth2.GrantType(req.GrantType)
	grantHandler, ok := h.grantRegistry.Get(grantType)
	if !ok || grantHandler == nil {
		c.JSON(http.StatusBadRequest, pkgoauth2.Error{
			Code:        "unsupported_grant_type",
			Description: "unsupported grant_type",
		})
		return
	}

	result, err := grantHandler.Exchange(c.Request.Context(), pluginport.ExchangeInput{
		GrantType:         grantType,
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		ReplayFingerprint: buildRefreshReplayFingerprint(clientID, string(clientAuth.Method), c.ClientIP(), c.Request.UserAgent()),
		Code:              req.Code,
		RedirectURI:       req.RedirectURI,
		CodeVerifier:      req.CodeVerifier,
		RefreshToken:      req.RefreshToken,
		DeviceCode:        req.DeviceCode,
		Username:          req.Username,
		Password:          req.Password,
		Scopes:            req.ScopeList(),
	})
	if err != nil {
		log.Printf("token exchange failed grant_type=%s client_id=%s err=%v", req.GrantType, clientID, err)
		status := http.StatusBadRequest
		oauthErr := pkgoauth2.Error{
			Code:        "invalid_grant",
			Description: err.Error(),
		}

		switch {
		case errors.Is(err, apptoken.ErrInvalidClient):
			status = http.StatusUnauthorized
			oauthErr.Code = "invalid_client"
		case errors.Is(err, apptoken.ErrInvalidScope):
			oauthErr.Code = "invalid_scope"
		case errors.Is(err, apptoken.ErrUnsupportedGrantType):
			oauthErr.Code = "unsupported_grant_type"
		case errors.Is(err, apptoken.ErrAuthorizationPending):
			oauthErr.Code = "authorization_pending"
			oauthErr.Description = err.Error()
		case errors.Is(err, apptoken.ErrSlowDown):
			oauthErr.Code = "slow_down"
			oauthErr.Description = err.Error()
		case errors.Is(err, apptoken.ErrAccessDenied):
			oauthErr.Code = "access_denied"
			oauthErr.Description = err.Error()
		case errors.Is(err, apptoken.ErrInvalidCode),
			errors.Is(err, apptoken.ErrInvalidRedirectURI),
			errors.Is(err, apptoken.ErrInvalidCodeVerifier),
			errors.Is(err, apptoken.ErrInvalidRefreshToken),
			errors.Is(err, apptoken.ErrInvalidDeviceCode),
			errors.Is(err, apptoken.ErrInvalidUserCredentials):
			oauthErr.Code = "invalid_grant"
		default:
			status = http.StatusInternalServerError
			oauthErr.Code = "server_error"
			oauthErr.Description = "token issuance failed"
		}

		c.JSON(status, oauthErr)
		return
	}

	c.JSON(http.StatusOK, pkgoauth2.TokenResponse{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		Scope:        result.Scope,
		RefreshToken: result.RefreshToken,
		IDToken:      result.IDToken,
	})
}

func buildRefreshReplayFingerprint(clientID, authMethod, clientIP, userAgent string) string {
	sum := sha256.Sum256([]byte(clientID + "|" + authMethod + "|" + clientIP + "|" + userAgent))
	return hex.EncodeToString(sum[:])
}
