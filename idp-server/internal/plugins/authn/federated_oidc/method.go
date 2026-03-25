package federated_oidc

import (
	"context"

	appauthn "idp-server/internal/application/authn"
	"idp-server/internal/ports/federation"
	pluginport "idp-server/internal/ports/plugin"
)

type Method struct {
	name      string
	connector federation.OIDCConnector
}

func NewMethod(connector federation.OIDCConnector) *Method {
	return &Method{
		name:      "federated_oidc",
		connector: connector,
	}
}

func (m *Method) Name() string {
	return m.name
}

func (m *Method) Type() pluginport.AuthnMethodType {
	return pluginport.AuthnMethodTypeFederatedOIDC
}

func (m *Method) Authenticate(ctx context.Context, input pluginport.AuthenticateInput) (*pluginport.AuthenticateResult, error) {
	if m.connector == nil {
		return nil, appauthn.ErrUnsupportedMethod
	}

	result, err := m.connector.Authenticate(ctx, federation.OIDCAuthenticateInput{
		RedirectURI: input.RedirectURI,
		ReturnTo:    input.ReturnTo,
		State:       input.State,
		Code:        input.Code,
		Nonce:       input.Nonce,
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, appauthn.ErrInvalidCredentials
	}

	return &pluginport.AuthenticateResult{
		Handled:          true,
		Authenticated:    result.Authenticated,
		Subject:          result.Subject,
		IdentityProvider: m.name,
		Username:         result.Username,
		DisplayName:      result.DisplayName,
		Email:            result.Email,
		RedirectURI:      result.RedirectURI,
	}, nil
}
