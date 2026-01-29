package handlers

import (
	"net/http"
	"strings"
	"sync"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
	"github.com/elazarl/goproxy"
)

// HexRepositoryHandler handles requests to private hex repositories, adding auth
type HexRepositoryHandler struct {
	credentials     []hexRepositoryCredentials
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
}

type hexRepositoryCredentials struct {
	url     string
	authKey string
}

func NewHexRepositoryHandler(creds config.Credentials) *HexRepositoryHandler {
	handler := HexRepositoryHandler{
		credentials:     []hexRepositoryCredentials{},
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
	}

	for _, cred := range creds {
		if cred["type"] != "hex_repository" {
			continue
		}

		url := cred.GetString("url")

		oidcCredential, _ := oidc.CreateOIDCCredential(cred)
		if oidcCredential != nil {
			if url != "" {
				handler.oidcCredentials[url] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for hex repository: %s", oidcCredential.Provider(), url)
			}
			continue
		}

		authKey := cred.GetString("auth-key")
		if authKey == "" {
			continue
		}

		hexRepositoryCred := hexRepositoryCredentials{
			url:     url,
			authKey: authKey,
		}

		handler.credentials = append(handler.credentials, hexRepositoryCred)
	}

	return &handler
}

// HandleRequest adds auth to a registry request
func (h *HexRepositoryHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	// Try OIDC credentials first
	if oidc.TryAuthOIDCRequestWithPrefix(&h.mutex, h.oidcCredentials, req, ctx) {
		return req, nil
	}

	// Fall back to static credentials
	if !shouldBeAuthenticated(req) {
		return req, nil
	}

	for _, cred := range h.credentials {
		if !helpers.UrlMatchesRequest(req, cred.url, true) {
			continue
		}

		logging.RequestLogf(ctx, "* authenticating hex repository request (host: %s)", req.URL.Hostname())
		req.Header.Set("authorization", cred.authKey)

		return req, nil
	}

	return req, nil
}

func shouldBeAuthenticated(req *http.Request) bool {
	return !strings.HasSuffix(req.URL.Path, "/public_key")
}
