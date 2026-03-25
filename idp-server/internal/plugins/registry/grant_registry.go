package registry

import pluginport "idp-server/internal/ports/plugin"

type GrantRegistry struct {
	handlers map[pluginport.GrantHandlerType]pluginport.GrantHandler
}

func NewGrantRegistry(handlers ...pluginport.GrantHandler) *GrantRegistry {
	registry := &GrantRegistry{
		handlers: make(map[pluginport.GrantHandlerType]pluginport.GrantHandler, len(handlers)),
	}

	for _, handler := range handlers {
		if handler == nil {
			continue
		}
		registry.handlers[handler.Type()] = handler
	}

	return registry
}

func (r *GrantRegistry) Register(handler pluginport.GrantHandler) {
	if r.handlers == nil {
		r.handlers = make(map[pluginport.GrantHandlerType]pluginport.GrantHandler)
	}
	if handler == nil {
		return
	}
	r.handlers[handler.Type()] = handler
}

func (r *GrantRegistry) Get(handlerType pluginport.GrantHandlerType) (pluginport.GrantHandler, bool) {
	handler, ok := r.handlers[handlerType]
	return handler, ok
}
