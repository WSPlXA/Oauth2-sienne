package clientauth

import (
	"context"
	"encoding/base64"
	"strings"

	apptoken "idp-server/internal/application/token"
	pluginregistry "idp-server/internal/plugins/registry"
	pluginport "idp-server/internal/ports/plugin"
	"idp-server/internal/ports/repository"
)

type Authenticator interface {
	Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error)
}

type AuthenticateInput struct {
	AuthorizationHeader string
	ClientID            string
	ClientSecret        string
}

type AuthenticateResult struct {
	ClientID     string
	ClientSecret string
	Method       pluginport.ClientAuthMethodType
}

type Service struct {
	clients  repository.ClientRepository
	registry *pluginregistry.ClientAuthRegistry
}

func NewService(clients repository.ClientRepository, registry *pluginregistry.ClientAuthRegistry) *Service {
	return &Service{
		clients:  clients,
		registry: registry,
	}
}

func (s *Service) Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error) {
	if s.clients == nil || s.registry == nil {
		return nil, apptoken.ErrInvalidClient
	}

	clientID := extractClientID(input.AuthorizationHeader, input.ClientID)
	if clientID == "" {
		return nil, apptoken.ErrInvalidClient
	}

	client, err := s.clients.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil || client.Status != "active" {
		return nil, apptoken.ErrInvalidClient
	}

	methodType := normalizeClientAuthMethod(client.TokenEndpointAuthMethod, client.AuthMethods)
	authenticator, ok := s.registry.Get(methodType)
	if !ok || authenticator == nil {
		return nil, apptoken.ErrInvalidClient
	}

	result, err := authenticator.Authenticate(ctx, pluginport.ClientAuthenticateInput{
		Client:              client,
		AuthorizationHeader: input.AuthorizationHeader,
		ClientID:            input.ClientID,
		ClientSecret:        input.ClientSecret,
	})
	if err != nil {
		return nil, err
	}
	if result == nil || strings.TrimSpace(result.ClientID) == "" {
		return nil, apptoken.ErrInvalidClient
	}
	if result.ClientID != client.ClientID {
		return nil, apptoken.ErrInvalidClient
	}

	return &AuthenticateResult{
		ClientID:     result.ClientID,
		ClientSecret: result.ClientSecret,
		Method:       result.Method,
	}, nil
}

func extractClientID(authorizationHeader, bodyClientID string) string {
	if strings.HasPrefix(authorizationHeader, "Basic ") {
		payload := strings.TrimPrefix(authorizationHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[0])
			}
		}
	}

	return strings.TrimSpace(bodyClientID)
}

func normalizeClientAuthMethod(primary string, fallbacks []string) pluginport.ClientAuthMethodType {
	method := pluginport.ClientAuthMethodType(strings.ToLower(strings.TrimSpace(primary)))
	if method != "" {
		return method
	}
	for _, candidate := range fallbacks {
		method = pluginport.ClientAuthMethodType(strings.ToLower(strings.TrimSpace(candidate)))
		if method != "" {
			return method
		}
	}
	return pluginport.ClientAuthMethodNone
}
