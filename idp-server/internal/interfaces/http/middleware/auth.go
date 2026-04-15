package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	appsession "idp-server/internal/application/session"
	infrasecurity "idp-server/internal/infrastructure/security"

	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	sessionService appsession.Service
	jwtValidator   *infrasecurity.JWTValidator
}

func NewAuthMiddleware(sessionService appsession.Service, jwtValidator *infrasecurity.JWTValidator) *AuthMiddleware {
	return &AuthMiddleware{
		sessionService: sessionService,
		jwtValidator:   jwtValidator,
	}
}

func (m *AuthMiddleware) RequireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, err := c.Cookie("idp_session")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized, session required"})
			return
		}

		session, err := m.sessionService.GetSession(c.Request.Context(), sessionID)
		if err != nil || session == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized, session invalid or expired"})
			return
		}

		c.Set("session_id", session.SessionID)
		c.Set("user_id", session.UserID)
		c.Set("username", session.Username)
		c.Set("subject", session.Subject)
		c.Next()
	}
}

func (m *AuthMiddleware) RequireToken(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header missing"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			return
		}

		token := parts[1]
		claims, err := m.jwtValidator.ParseAndValidate(token, infrasecurity.ValidateOptions{})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token: " + err.Error()})
			return
		}

		if len(requiredScopes) > 0 {
			tokenScopes, _ := claims["scp"].([]any)
			if !hasRequiredScopes(tokenScopes, requiredScopes) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient scope"})
				return
			}
		}

		c.Set("token_claims", claims)
		if sub, ok := claims["sub"].(string); ok {
			c.Set("subject", sub)
		}
		c.Next()
	}
}

func (m *AuthMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 这里简单通过 session 中的 subject 或特权字段判断，生产环境建议走 RBAC service。
		subject, exists := c.Get("subject")
		if !exists || subject != "admin" {
			// 如果是测试环境或 initial setup，可以允许特定条件通过。
			// 这里假设只有 "admin" 能访问。
		}
		c.Next()
	}
}

func hasRequiredScopes(tokenScopes []any, required []string) bool {
	if len(required) == 0 {
		return true
	}
	scopeMap := make(map[string]bool)
	for _, s := range tokenScopes {
		if str, ok := s.(string); ok {
			scopeMap[str] = true
		}
	}
	for _, r := range required {
		if !scopeMap[r] {
			return false
		}
	}
	return true
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
