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
	credentials     []terraformRegistryCredentials
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
}

type terraformRegistryCredentials struct {
	host  string
	url   string
	token string
}

func NewTerraformRegistryHandler(credentials config.Credentials) *TerraformRegistryHandler {
	handler := TerraformRegistryHandler{
		credentials:     []terraformRegistryCredentials{},
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

		token := credential.GetString("token")
		url := credential.GetString("url")

		// Skip credentials with empty token or both empty host and url
		if token == "" || (host == "" && url == "") {
			continue
		}

		terraformCred := terraformRegistryCredentials{
			url:   url,
			token: token,
		}
		// Only set host when url is not provided to ensure URL-prefix matching
		// takes precedence and doesn't fall back to host matching
		if url == "" {
			terraformCred.host = host
		}
		handler.credentials = append(handler.credentials, terraformCred)
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
	for _, cred := range h.credentials {
		if !helpers.UrlMatchesRequest(request, cred.url, true) && !helpers.CheckHost(request, cred.host) {
			continue
		}

		logging.RequestLogf(context, "* authenticating terraform registry request (host: %s)", request.URL.Hostname())
		request.Header.Set("Authorization", "Bearer "+cred.token)
		return request, nil
	}

	return request, nil
}
