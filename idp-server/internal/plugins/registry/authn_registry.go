package registry

import pluginport "idp-server/internal/ports/plugin"

type AuthnRegistry struct {
	methods map[pluginport.AuthnMethodType]pluginport.AuthnMethod
}

func NewAuthnRegistry(methods ...pluginport.AuthnMethod) *AuthnRegistry {
	registry := &AuthnRegistry{
		methods: make(map[pluginport.AuthnMethodType]pluginport.AuthnMethod, len(methods)),
	}

	for _, method := range methods {
		if method == nil {
			continue
		}
		registry.methods[method.Type()] = method
	}

	return registry
}

func (r *AuthnRegistry) Register(method pluginport.AuthnMethod) {
	if r.methods == nil {
		r.methods = make(map[pluginport.AuthnMethodType]pluginport.AuthnMethod)
	}
	if method == nil {
		return
	}
	r.methods[method.Type()] = method
}

func (r *AuthnRegistry) Get(methodType pluginport.AuthnMethodType) (pluginport.AuthnMethod, bool) {
	method, ok := r.methods[methodType]
	return method, ok
}
