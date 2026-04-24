package handler

import (
	"errors"
	"net/http"
	neturl "net/url"
	"strings"

	appshorturl "idp-server/internal/application/shorturl"
	"idp-server/internal/interfaces/http/dto"

	"github.com/gin-gonic/gin"
)

type ShortURLHandler struct {
	service appshorturl.Manager
}

func NewShortURLHandler(service appshorturl.Manager) *ShortURLHandler {
	return &ShortURLHandler{service: service}
}

func (h *ShortURLHandler) Create(c *gin.Context) {
	var req dto.CreateShortURLRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid short url request"})
		return
	}

	result, err := h.service.Create(c.Request.Context(), appshorturl.CreateInput{
		Code:      req.Code,
		TargetURL: req.TargetURL,
		ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, appshorturl.ErrCodeAlreadyExists):
			status = http.StatusConflict
		case errors.Is(err, appshorturl.ErrInvalidCode),
			errors.Is(err, appshorturl.ErrInvalidTargetURL),
			errors.Is(err, appshorturl.ErrInvalidExpiry):
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"code":       result.Code,
		"short_url":  buildShortURL(c, result.Code),
		"target_url": result.TargetURL,
		"expires_at": result.ExpiresAt,
		"created_at": result.CreatedAt,
	})
}

func (h *ShortURLHandler) Redirect(c *gin.Context) {
	result, err := h.service.Resolve(c.Request.Context(), appshorturl.ResolveInput{
		Code: c.Param("code"),
	})
	if err != nil {
		switch {
		case errors.Is(err, appshorturl.ErrInvalidCode),
			errors.Is(err, appshorturl.ErrLinkNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "short url not found"})
		case errors.Is(err, appshorturl.ErrLinkExpired):
			c.JSON(http.StatusGone, gin.H{"error": "short url expired"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "short url redirect failed"})
		}
		return
	}

	c.Redirect(http.StatusFound, result.TargetURL)
}

func buildShortURL(c *gin.Context, code string) string {
	scheme := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto"))
	if scheme == "" {
		if c.Request.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := strings.TrimSpace(c.GetHeader("X-Forwarded-Host"))
	if host == "" {
		host = c.Request.Host
	}
	return scheme + "://" + host + "/s/" + neturl.PathEscape(code)
}
