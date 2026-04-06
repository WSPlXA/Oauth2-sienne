package device_code

import (
	"context"
	"errors"

	apptoken "idp-server/internal/application/token"
	pluginport "idp-server/internal/ports/plugin"
	pkgoauth2 "idp-server/pkg/oauth2"
)

type Handler struct {
	name      string
	exchanger apptoken.Exchanger
}

func NewHandler(exchanger apptoken.Exchanger) *Handler {
	return &Handler{
		name:      "device_code",
		exchanger: exchanger,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Type() pluginport.GrantHandlerType {
	return pkgoauth2.GrantTypeDeviceCode
}

func (h *Handler) Exchange(ctx context.Context, input pluginport.ExchangeInput) (*pluginport.ExchangeResult, error) {
	if h.exchanger == nil {
		return nil, errors.New("grant handler is not configured")
	}
	if input.GrantType == "" {
		input.GrantType = pkgoauth2.GrantTypeDeviceCode
	}
	if input.GrantType != pkgoauth2.GrantTypeDeviceCode {
		return nil, apptoken.ErrUnsupportedGrantType
	}

	result, err := h.exchanger.Exchange(ctx, apptoken.ExchangeInput{
		GrantType:    input.GrantType,
		ClientID:     input.ClientID,
		ClientSecret: input.ClientSecret,
		DeviceCode:   input.DeviceCode,
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	return &pluginport.ExchangeResult{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
		Scope:        result.Scope,
		IDToken:      result.IDToken,
	}, nil
}
