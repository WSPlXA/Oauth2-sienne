package registry

import pluginport "idp-server/internal/ports/plugin"

type ClientAuthRegistry struct {
	authenticators map[pluginport.ClientAuthMethodType]pluginport.ClientAuthenticator
}

func NewClientAuthRegistry(authenticators ...pluginport.ClientAuthenticator) *ClientAuthRegistry {
	registry := &ClientAuthRegistry{
		authenticators: make(map[pluginport.ClientAuthMethodType]pluginport.ClientAuthenticator, len(authenticators)),
	}

	for _, authenticator := range authenticators {
		if authenticator == nil {
			continue
		}
		registry.authenticators[authenticator.Type()] = authenticator
	}

	return registry
}

func (r *ClientAuthRegistry) Register(authenticator pluginport.ClientAuthenticator) {
	if r.authenticators == nil {
		r.authenticators = make(map[pluginport.ClientAuthMethodType]pluginport.ClientAuthenticator)
	}
	if authenticator == nil {
		return
	}
	r.authenticators[authenticator.Type()] = authenticator
}

func (r *ClientAuthRegistry) Get(methodType pluginport.ClientAuthMethodType) (pluginport.ClientAuthenticator, bool) {
	authenticator, ok := r.authenticators[methodType]
	return authenticator, ok
}
