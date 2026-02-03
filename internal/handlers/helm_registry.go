package handlers

import (
	"net/http"
	"sync"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

// HelmRegistryHandler handles requests to helm registries, adding auth.
type HelmRegistryHandler struct {
	credentials     []helmRegistryCredentials
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
}

type helmRegistryCredentials struct {
	registry string
	username string
	password string
}

// NewHelmRegistryHandler returns a new HelmRegistryHandler.
func NewHelmRegistryHandler(creds config.Credentials) *HelmRegistryHandler {
	handler := HelmRegistryHandler{
		credentials:     []helmRegistryCredentials{},
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
	}

	for _, cred := range creds {
		if cred["type"] != "helm_registry" {
			continue
		}

		registry := cred.GetString("registry")
		if registry == "" {
			registry = cred.Host()
		}

		oidcCredential, _ := oidc.CreateOIDCCredential(cred)
		if oidcCredential != nil {
			if registry != "" {
				handler.oidcCredentials[registry] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for helm registry: %s", oidcCredential.Provider(), registry)
			}
			continue
		}

		helmCred := helmRegistryCredentials{
			registry: registry,
			username: cred.GetString("username"),
			password: cred.GetString("password"),
		}
		handler.credentials = append(handler.credentials, helmCred)
	}

	return &handler
}

// HandleRequest adds auth to a helm registry request
func (h *HelmRegistryHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	// Try OIDC credentials first
	if oidc.TryAuthOIDCRequestWithPrefix(&h.mutex, h.oidcCredentials, req, ctx) {
		return req, nil
	}

	// Fall back to static credentials
	for _, cred := range h.credentials {
		if !helpers.UrlMatchesRequest(req, cred.registry, true) {
			continue
		}

		logging.RequestLogf(ctx, "* authenticating helm registry request (host: %s)", req.URL.Hostname())
		req.SetBasicAuth(cred.username, cred.password)

		return req, nil
	}

	return req, nil
}
