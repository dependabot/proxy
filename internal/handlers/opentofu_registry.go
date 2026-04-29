package handlers

import (
	"net/http"
	"sort"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

type OpenTofuRegistryHandler struct {
	credentials  []openTofuRegistryCredentials
	oidcRegistry *oidc.OIDCRegistry
}

type openTofuRegistryCredentials struct {
	host  string
	url   string
	token string
}

func NewOpenTofuRegistryHandler(credentials config.Credentials) *OpenTofuRegistryHandler {
	handler := OpenTofuRegistryHandler{
		credentials:  []openTofuRegistryCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(),
	}

	for _, credential := range credentials {
		if credential["type"] != "opentofu_registry" {
			continue
		}

		// OIDC credentials are not used as static credentials.
		if oidcCred, _, _ := handler.oidcRegistry.Register(credential, []string{"url"}, "opentofu registry"); oidcCred != nil {
			continue
		}

		host := credential.Host()
		token := credential.GetString("token")
		url := credential.GetString("url")

		// Skip credentials with empty token or both empty host and url
		if token == "" || (host == "" && url == "") {
			continue
		}

		opentofuCred := openTofuRegistryCredentials{
			url:   url,
			token: token,
		}
		// Only set host when url is not provided to ensure URL-prefix matching
		// takes precedence and doesn't fall back to host matching
		if url == "" {
			opentofuCred.host = host
		}
		handler.credentials = append(handler.credentials, opentofuCred)
	}

	// Sort credentials by URL length descending (longest first) to ensure
	// more specific URLs match before shorter ones. Using SliceStable for
	// deterministic ordering when URL lengths are equal.
	sort.SliceStable(handler.credentials, func(i, j int) bool {
		return len(handler.credentials[i].url) > len(handler.credentials[j].url)
	})

	return &handler
}

func (h *OpenTofuRegistryHandler) HandleRequest(request *http.Request, context *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if request.URL.Scheme != "https" || !helpers.MethodPermitted(request, "GET", "HEAD") {
		return request, nil
	}

	// Try OIDC credentials first
	if h.oidcRegistry.TryAuth(request, context) {
		return request, nil
	}

	// Fall back to static credentials
	for _, cred := range h.credentials {
		if !urlMatchesRequestWithBoundary(request, cred.url) && !helpers.CheckHost(request, cred.host) {
			continue
		}

		logging.RequestLogf(context, "* authenticating opentofu registry request (host: %s)", request.URL.Hostname())
		request.Header.Set("Authorization", "Bearer "+cred.token)
		return request, nil
	}

	return request, nil
}
