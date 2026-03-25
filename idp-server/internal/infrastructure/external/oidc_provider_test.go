package external

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	cacheport "idp-server/internal/ports/cache"
	"idp-server/internal/ports/federation"
)

func TestOIDCProviderAuthenticateViaUserInfo(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"userinfo_endpoint":      server.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("code"); got != "auth-code" {
			t.Fatalf("code = %q", got)
		}
		if got := r.Form.Get("redirect_uri"); got != "http://localhost:8080/login/callback" {
			t.Fatalf("redirect_uri = %q", got)
		}
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			t.Fatal("expected basic auth")
		}
		if clientID != "client-id" || clientSecret != "client-secret" {
			t.Fatalf("basic auth = %q/%q", clientID, clientSecret)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token",
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Fatalf("authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":                "external-subject",
			"preferred_username": "alice.ext",
			"name":               "Alice External",
			"email":              "alice@example.com",
		})
	})

	replayCache := newStubReplayProtectionRepository()
	provider := NewOIDCProviderWithReplayCache(OIDCProviderConfig{
		Issuer:       server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "http://localhost:8080/login/callback",
	}, replayCache)

	start, err := provider.Authenticate(context.Background(), federation.OIDCAuthenticateInput{
		ReturnTo: "/oauth2/authorize?client_id=demo",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if start.Authenticated {
		t.Fatal("expected redirect challenge")
	}
	state := extractQueryValue(t, start.RedirectURI, "state")
	if state == "" {
		t.Fatal("expected state in redirect uri")
	}

	result, err := provider.Authenticate(context.Background(), federation.OIDCAuthenticateInput{
		Code:  "auth-code",
		State: state,
	})
	if err != nil {
		t.Fatalf("Authenticate callback returned error: %v", err)
	}
	if !result.Authenticated {
		t.Fatal("expected authenticated result")
	}
	if result.Subject != "external-subject" {
		t.Fatalf("subject = %q", result.Subject)
	}
	if result.Username != "alice.ext" {
		t.Fatalf("username = %q", result.Username)
	}
	if result.RedirectURI != "/oauth2/authorize?client_id=demo" {
		t.Fatalf("redirect uri = %q", result.RedirectURI)
	}
}

func TestOIDCProviderAuthenticateViaIDTokenFallback(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	issuedNonce := ""

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://issuer.example.com",
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idToken := buildUnsignedJWT(t, map[string]any{
			"iss":   "https://issuer.example.com",
			"aud":   "client-id",
			"sub":   "oidc-user",
			"nonce": issuedNonce,
			"email": "oidc@example.com",
			"name":  "OIDC User",
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token": idToken,
		})
	})

	replayCache := newStubReplayProtectionRepository()
	provider := NewOIDCProviderWithReplayCache(OIDCProviderConfig{
		Issuer:       server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "http://localhost:8080/login/callback",
	}, replayCache)

	start, err := provider.Authenticate(context.Background(), federation.OIDCAuthenticateInput{
		ReturnTo: "/after-login",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	state := extractQueryValue(t, start.RedirectURI, "state")
	issuedNonce = extractQueryValue(t, start.RedirectURI, "nonce")

	result, err := provider.Authenticate(context.Background(), federation.OIDCAuthenticateInput{
		Code:  "auth-code",
		State: state,
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if result.Subject != "oidc-user" {
		t.Fatalf("subject = %q", result.Subject)
	}
	if result.Email != "oidc@example.com" {
		t.Fatalf("email = %q", result.Email)
	}
}

func buildUnsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "."
}

func extractQueryValue(t *testing.T, rawURL, key string) string {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return parsed.Query().Get(key)
}

type stubReplayProtectionRepository struct {
	state map[string]map[string]string
}

func newStubReplayProtectionRepository() *stubReplayProtectionRepository {
	return &stubReplayProtectionRepository{
		state: make(map[string]map[string]string),
	}
}

func (r *stubReplayProtectionRepository) SaveState(_ context.Context, state string, value map[string]string, _ time.Duration) error {
	copied := make(map[string]string, len(value))
	for k, v := range value {
		copied[k] = v
	}
	r.state[state] = copied
	return nil
}

func (r *stubReplayProtectionRepository) GetState(_ context.Context, state string) (map[string]string, error) {
	value, ok := r.state[state]
	if !ok {
		return nil, nil
	}
	copied := make(map[string]string, len(value))
	for k, v := range value {
		copied[k] = v
	}
	return copied, nil
}

func (r *stubReplayProtectionRepository) DeleteState(_ context.Context, state string) error {
	delete(r.state, state)
	return nil
}

func (r *stubReplayProtectionRepository) SaveNonce(_ context.Context, _ string, _ time.Duration) error {
	return nil
}

func (r *stubReplayProtectionRepository) ExistsNonce(_ context.Context, _ string) (bool, error) {
	return false, nil
}

var _ cacheport.ReplayProtectionRepository = (*stubReplayProtectionRepository)(nil)
