package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appshorturl "idp-server/internal/application/shorturl"

	"github.com/gin-gonic/gin"
)

type stubShortURLManager struct {
	createResult  *appshorturl.CreateResult
	createErr     error
	createInput   appshorturl.CreateInput
	resolveResult *appshorturl.ResolveResult
	resolveErr    error
	resolveInput  appshorturl.ResolveInput
}

func (s *stubShortURLManager) Create(_ context.Context, input appshorturl.CreateInput) (*appshorturl.CreateResult, error) {
	s.createInput = input
	return s.createResult, s.createErr
}

func (s *stubShortURLManager) Resolve(_ context.Context, input appshorturl.ResolveInput) (*appshorturl.ResolveResult, error) {
	s.resolveInput = input
	return s.resolveResult, s.resolveErr
}

func TestShortURLHandlerCreate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	createdAt := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	service := &stubShortURLManager{
		createResult: &appshorturl.CreateResult{
			Code:      "go2026",
			TargetURL: "https://example.com/docs",
			CreatedAt: createdAt,
		},
	}
	router := gin.New()
	router.POST("/admin/short-urls", NewShortURLHandler(service).Create)

	body, err := json.Marshal(map[string]any{
		"code":       "go2026",
		"target_url": "https://example.com/docs",
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/short-urls", bytes.NewReader(body))
	req.Host = "idp.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if service.createInput.Code != "go2026" {
		t.Fatalf("code = %q, want go2026", service.createInput.Code)
	}
	if service.createInput.TargetURL != "https://example.com/docs" {
		t.Fatalf("target url = %q", service.createInput.TargetURL)
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`"short_url":"https://idp.example.com/s/go2026"`)) {
		t.Fatalf("response body = %s", recorder.Body.String())
	}
}

func TestShortURLHandlerRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubShortURLManager{
		resolveResult: &appshorturl.ResolveResult{
			Code:      "go2026",
			TargetURL: "https://example.com/docs",
		},
	}
	router := gin.New()
	router.GET("/s/:code", NewShortURLHandler(service).Redirect)

	req := httptest.NewRequest(http.MethodGet, "/s/go2026", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if recorder.Header().Get("Location") != "https://example.com/docs" {
		t.Fatalf("Location = %q", recorder.Header().Get("Location"))
	}
	if service.resolveInput.Code != "go2026" {
		t.Fatalf("resolved code = %q", service.resolveInput.Code)
	}
}
