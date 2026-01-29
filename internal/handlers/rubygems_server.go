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

// RubyGemsServerHandler handles requests to rubygems servers, adding auth.
type RubyGemsServerHandler struct {
	credentials     []rubyGemsServerCredentials
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
}

type rubyGemsServerCredentials struct {
	host  string
	url   string
	token string
}

// NewRubyGemsServerHandler returns a new RubyGemsServerHandler.
func NewRubyGemsServerHandler(creds config.Credentials) *RubyGemsServerHandler {
	handler := RubyGemsServerHandler{
		credentials:     []rubyGemsServerCredentials{},
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
	}

	for _, cred := range creds {
		if cred["type"] != "rubygems_server" {
			continue
		}

		host := cred.Host()
		url := cred.GetString("url")

		oidcCredential, _ := oidc.CreateOIDCCredential(cred)
		if oidcCredential != nil {
			hostURL := url
			if hostURL == "" {
				hostURL = host
			}
			if hostURL != "" {
				handler.oidcCredentials[hostURL] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for rubygems server: %s", oidcCredential.Provider(), hostURL)
			}
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
	if oidc.TryAuthOIDCRequestWithPrefix(&h.mutex, h.oidcCredentials, req, ctx) {
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
