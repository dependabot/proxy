package handlers

import (
	"net/http"
	"sort"
	"strings"
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

	// Sort credentials by URL length descending (longest first) to ensure
	// more specific URLs match before shorter ones. Using SliceStable for
	// deterministic ordering when URL lengths are equal.
	sort.SliceStable(handler.credentials, func(i, j int) bool {
		return len(handler.credentials[i].url) > len(handler.credentials[j].url)
	})

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
		if !urlMatchesRequestWithBoundary(request, cred.url) && !helpers.CheckHost(request, cred.host) {
			continue
		}

		logging.RequestLogf(context, "* authenticating terraform registry request (host: %s)", request.URL.Hostname())
		request.Header.Set("Authorization", "Bearer "+cred.token)
		return request, nil
	}

	return request, nil
}

// urlMatchesRequestWithBoundary checks if the request URL matches the credential URL
// with proper path boundary checking.
func urlMatchesRequestWithBoundary(request *http.Request, credURL string) bool {
	if credURL == "" {
		return false
	}

	parsedURL, err := helpers.ParseURLLax(credURL)
	if err != nil {
		return false
	}

	if !helpers.AreHostnamesEqual(parsedURL.Hostname(), request.URL.Hostname()) {
		return false
	}

	urlPort := parsedURL.Port()
	if urlPort == "" {
		urlPort = "443"
	}

	reqPort := request.URL.Port()
	if reqPort == "" {
		reqPort = "443"
	}

	if urlPort != reqPort {
		return false
	}

	credPath := strings.TrimRight(parsedURL.Path, "/")
	reqPath := request.URL.Path

	if credPath == "" {
		// Empty path matches everything on the host
		return true
	}

	if reqPath == credPath {
		return true
	}

	// Check if request path starts with credPath followed by /
	if strings.HasPrefix(reqPath, credPath+"/") {
		return true
	}

	return false
}
