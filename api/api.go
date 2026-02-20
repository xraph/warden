// Package api provides HTTP handlers for the Warden authorization engine.
package api

import (
	"net/http"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
)

// API wires all Warden HTTP handlers together.
type API struct {
	eng    *warden.Engine
	router forge.Router
}

// New creates an API from an Engine and a Forge router.
func New(eng *warden.Engine, router forge.Router) *API {
	return &API{eng: eng, router: router}
}

// Handler returns the fully assembled http.Handler with all routes.
func (a *API) Handler() http.Handler {
	if a.router == nil {
		a.router = forge.NewRouter()
	}
	if err := a.RegisterRoutes(a.router); err != nil {
		panic("warden: register routes: " + err.Error())
	}
	return a.router.Handler()
}

// RegisterRoutes registers all API routes into the given Forge router.
func (a *API) RegisterRoutes(router forge.Router) error {
	registerers := []func(forge.Router) error{
		a.registerCheckRoutes,
		a.registerRoleRoutes,
		a.registerPermissionRoutes,
		a.registerAssignmentRoutes,
		a.registerRelationRoutes,
		a.registerPolicyRoutes,
		a.registerResourceTypeRoutes,
		a.registerCheckLogRoutes,
	}
	for _, fn := range registerers {
		if err := fn(router); err != nil {
			return err
		}
	}
	return nil
}
