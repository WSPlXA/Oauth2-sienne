package device

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	cacheport "idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
)

type Service struct {
	clients      repository.ClientRepository
	deviceCodes  cacheport.DeviceCodeRepository
	sessions     repository.SessionRepository
	sessionCache cacheport.SessionCacheRepository
	deviceTTL    time.Duration
	interval     time.Duration
	now          func() time.Time
}

func NewService(
	clients repository.ClientRepository,
	deviceCodes cacheport.DeviceCodeRepository,
	sessions repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
	deviceTTL time.Duration,
	interval time.Duration,
) *Service {
	return &Service{
		clients:      clients,
		deviceCodes:  deviceCodes,
		sessions:     sessions,
		sessionCache: sessionCache,
		deviceTTL:    deviceTTL,
		interval:     interval,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (s *Service) Start(ctx context.Context, input StartInput) (*StartResult, error) {
	client, err := s.clients.FindByClientID(ctx, strings.TrimSpace(input.ClientID))
	if err != nil {
		return nil, err
	}
	if client == nil || client.Status != "active" || !contains(client.GrantTypes, "urn:ietf:params:oauth:grant-type:device_code") {
		return nil, ErrInvalidClient
	}

	scopes := normalizeScopes(input.Scopes)
	if len(scopes) == 0 {
		scopes = append([]string(nil), client.Scopes...)
	}
	if !allContained(scopes, client.Scopes) {
		return nil, ErrInvalidScope
	}

	deviceCode, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	userCode, err := randomUserCode()
	if err != nil {
		return nil, err
	}
	scopeJSON, _ := json.Marshal(scopes)
	expiresAt := s.now().Add(s.deviceTTL)
	if err := s.deviceCodes.Save(ctx, cacheport.DeviceCodeEntry{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   client.ClientID,
		ClientName: client.ClientName,
		ScopesJSON: string(scopeJSON),
		Status:     "pending",
		ExpiresAt:  expiresAt,
		Interval:   int64(s.interval / time.Second),
	}, s.deviceTTL); err != nil {
		return nil, err
	}

	return &StartResult{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ExpiresAt:  expiresAt,
		Interval:   int64(s.interval / time.Second),
		ClientID:   client.ClientID,
	}, nil
}

func (s *Service) Prepare(ctx context.Context, input PrepareInput) (*PrepareResult, error) {
	entry, _, _, err := s.loadContext(ctx, input.SessionID, input.UserCode)
	if err != nil {
		return nil, err
	}

	scopes := decodeScopes(entry.ScopesJSON)
	return &PrepareResult{
		UserCode:   entry.UserCode,
		ClientID:   entry.ClientID,
		ClientName: entry.ClientName,
		Scopes:     scopes,
	}, nil
}

func (s *Service) Decide(ctx context.Context, input DecideInput) (*DecideResult, error) {
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action != "approve" && action != "deny" {
		return nil, ErrInvalidAction
	}

	entry, sessionUserID, subject, err := s.loadContext(ctx, input.SessionID, input.UserCode)
	if err != nil {
		return nil, err
	}
	if action == "deny" {
		if err := s.deviceCodes.Deny(ctx, entry.UserCode, s.now()); err != nil {
			return nil, err
		}
		return &DecideResult{Approved: false}, nil
	}

	if err := s.deviceCodes.Approve(ctx, entry.UserCode, strconv.FormatInt(sessionUserID, 10), subject, s.now()); err != nil {
		return nil, err
	}
	return &DecideResult{Approved: true}, nil
}

func (s *Service) loadContext(ctx context.Context, sessionID string, userCode string) (*cacheport.DeviceCodeEntry, int64, string, error) {
	userCode = strings.ToUpper(strings.TrimSpace(userCode))
	if userCode == "" {
		return nil, 0, "", ErrInvalidUserCode
	}
	if s.deviceCodes == nil {
		return nil, 0, "", ErrInvalidUserCode
	}
	entry, err := s.deviceCodes.GetByUserCode(ctx, userCode)
	if err != nil {
		return nil, 0, "", err
	}
	if entry == nil || !entry.ExpiresAt.After(s.now()) || (entry.Status != "" && entry.Status != "pending") {
		return nil, 0, "", ErrInvalidUserCode
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, 0, "", ErrLoginRequired
	}

	if s.sessionCache != nil {
		cacheEntry, err := s.sessionCache.Get(ctx, sessionID)
		if err != nil {
			return nil, 0, "", err
		}
		if cacheEntry != nil && cacheEntry.Status == "active" && cacheEntry.ExpiresAt.After(s.now()) {
			userID, err := strconv.ParseInt(cacheEntry.UserID, 10, 64)
			if err == nil && userID > 0 {
				return entry, userID, cacheEntry.Subject, nil
			}
		}
	}

	sessionModel, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return nil, 0, "", err
	}
	if sessionModel == nil || sessionModel.LoggedOutAt != nil || !sessionModel.ExpiresAt.After(s.now()) {
		return nil, 0, "", ErrLoginRequired
	}
	return entry, sessionModel.UserID, sessionModel.Subject, nil
}

func decodeScopes(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var scopes []string
	if err := json.Unmarshal([]byte(raw), &scopes); err != nil {
		return nil
	}
	return scopes
}

func normalizeScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	return result
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func allContained(values, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		allowedSet[value] = struct{}{}
	}
	for _, value := range values {
		if _, ok := allowedSet[value]; !ok {
			return false
		}
	}
	return true
}

func randomToken(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, length)
	for i := range buf {
		out[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(out), nil
}

func randomUserCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, len(buf))
	for i := range buf {
		out[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return fmt.Sprintf("%s-%s", string(out[:4]), string(out[4:])), nil
}
