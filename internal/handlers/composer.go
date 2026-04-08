package handlers

import (
	"net/http"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

// ComposerHandler handles requests to PHP registries, adding auth.
type ComposerHandler struct {
	credentials  []composerCredentials
	oidcRegistry *oidc.OIDCRegistry
}

type composerCredentials struct {
	registry string
	url      string
	username string
	password string
	token    string
}

// NewComposerHandler returns a new ComposerHandler.
func NewComposerHandler(creds config.Credentials) *ComposerHandler {
	handler := ComposerHandler{
		credentials:  []composerCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(),
	}

	for _, cred := range creds {
		if cred["type"] != "composer_repository" {
			continue
		}

		registry := cred.GetString("registry")
		url := cred.GetString("url")

		// OIDC credentials are not used as static credentials.
		if oidcCred, _, _ := handler.oidcRegistry.Register(cred, []string{"url", "registry"}, "composer repository"); oidcCred != nil {
			continue
		}

		composerCred := composerCredentials{
			registry: registry,
			url:      url,
			username: cred.GetString("username"),
			password: cred.GetString("password"),
			token:    cred.GetString("token"),
		}
		handler.credentials = append(handler.credentials, composerCred)
	}

	return &handler
}

// HandleRequest adds auth to a composer registry request
func (h *ComposerHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	// Try OIDC credentials first
	if h.oidcRegistry.TryAuth(req, ctx) {
		return req, nil
	}

	// Fall back to static credentials
	for _, cred := range h.credentials {
		matchURL := cred.url
		if matchURL == "" {
			matchURL = cred.registry
		}
		if !helpers.UrlMatchesRequest(req, matchURL, true) {
			continue
		}

		if cred.token != "" {
			logging.RequestLogf(ctx, "* authenticating composer registry request (host: %s, token auth)", req.URL.Hostname())
			req.Header.Set("Authorization", "Bearer "+cred.token)
		} else {
			logging.RequestLogf(ctx, "* authenticating composer registry request (host: %s, basic auth)", req.URL.Hostname())
			req.SetBasicAuth(cred.username, cred.password)
		}

		return req, nil
	}

	return req, nil
}
