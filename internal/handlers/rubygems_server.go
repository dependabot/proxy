package handlers

import (
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

// RubyGemsServerHandler handles requests to rubygems servers, adding auth.
type RubyGemsServerHandler struct {
	credentials  []rubyGemsServerCredentials
	oidcRegistry *oidc.OIDCRegistry
}

type rubyGemsServerCredentials struct {
	host  string
	url   string
	token string
}

// NewRubyGemsServerHandler returns a new RubyGemsServerHandler.
func NewRubyGemsServerHandler(creds config.Credentials) *RubyGemsServerHandler {
	handler := RubyGemsServerHandler{
		credentials:  []rubyGemsServerCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(),
	}

	for _, cred := range creds {
		if cred["type"] != "rubygems_server" {
			continue
		}

		host := cred.Host()
		url := cred.GetString("url")

		// OIDC credentials are not used as static credentials.
		if oidcCred, _, _ := handler.oidcRegistry.Register(cred, []string{"url"}, "rubygems server"); oidcCred != nil {
			continue
		}

		serverCred := rubyGemsServerCredentials{
			host:  host,
			url:   url,
			token: cred.GetString("token"),
		}
		handler.credentials = append(handler.credentials, serverCred)
	}

	return &handler
}

// HandleRequest adds auth to a rubygems server request
func (h *RubyGemsServerHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
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
			matchURL = cred.host
		}
		if !helpers.UrlMatchesRequest(req, matchURL, true) {
			continue
		}

		logging.RequestLogf(ctx, "* authenticating rubygems server request (host: %s)", req.URL.Hostname())

		// ignore `found` because it's okay for the password to be an empty string
		username, password, _ := strings.Cut(cred.token, ":")
		req.SetBasicAuth(username, password)

		return req, nil
	}

	return req, nil
}
