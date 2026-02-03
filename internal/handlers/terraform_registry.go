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

type TerraformRegistryHandler struct {
	credentials     map[string]string
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
}

func NewTerraformRegistryHandler(credentials config.Credentials) *TerraformRegistryHandler {
	handler := TerraformRegistryHandler{
		credentials:     make(map[string]string),
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
	}

	for _, credential := range credentials {
		if credential["type"] != "terraform_registry" {
			continue
		}

		host := credential.Host()

		oidcCredential, _ := oidc.CreateOIDCCredential(credential)
		if oidcCredential != nil {
			if host != "" {
				handler.oidcCredentials[host] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for terraform registry: %s", oidcCredential.Provider(), host)
			}
			continue
		}

		handler.credentials[host] = credential.GetString("token")
	}
	return &handler
}

func (h *TerraformRegistryHandler) HandleRequest(request *http.Request, context *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if request.URL.Scheme != "https" || !helpers.MethodPermitted(request, "GET", "HEAD") {
		return request, nil
	}

	// Try OIDC credentials first
	if oidc.TryAuthOIDCRequestWithPrefix(&h.mutex, h.oidcCredentials, request, context) {
		return request, nil
	}

	// Fall back to static credentials
	host := request.URL.Hostname()
	token, ok := h.credentials[host]

	if !ok {
		return request, nil
	}

	logging.RequestLogf(context, "* authenticating terraform registry request (host: %s)", host)
	request.Header.Set("Authorization", "Bearer "+token)

	return request, nil
}
