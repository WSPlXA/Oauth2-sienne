package password

import (
	"context"

	pluginport "idp-server/internal/ports/plugin"
)

type Method struct {
	name string
}

func NewMethod() *Method {
	return &Method{name: "password"}
}

func (m *Method) Name() string {
	return m.name
}

func (m *Method) Type() pluginport.AuthnMethodType {
	return pluginport.AuthnMethodTypePassword
}

func (m *Method) Authenticate(ctx context.Context, input pluginport.AuthenticateInput) (*pluginport.AuthenticateResult, error) {
	_ = ctx
	return &pluginport.AuthenticateResult{
		Handled:       input.Username != "" || input.Password != "",
		Authenticated: false,
		Username:      input.Username,
	}, nil
}
