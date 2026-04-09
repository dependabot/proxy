package handlers

import (
	"net/http"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

type GoProxyServerHandler struct {
	credentials  []goProxyServerCredentials
	oidcRegistry *oidc.OIDCRegistry
}

type goProxyServerCredentials struct {
	url      string
	host     string
	username string
	password string
}

// NewGoProxyServerHandler returns a new GoProxyServerHandler.
func NewGoProxyServerHandler(creds config.Credentials) *GoProxyServerHandler {
	handler := GoProxyServerHandler{
		credentials:  []goProxyServerCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(),
	}

	for _, cred := range creds {
		if cred["type"] != "goproxy_server" {
			continue
		}

		url := cred.GetString("url")
		host := cred.GetString("host")

		// OIDC credentials are not used as static credentials.
		if oidcCred, _, _ := handler.oidcRegistry.Register(cred, []string{"url"}, "goproxy server"); oidcCred != nil {
			continue
		}

		if cred.GetString("password") == "" && cred.GetString("username") == "" {
			continue
		}

		repoCred := goProxyServerCredentials{
			url:      url,
			host:     host,
			username: cred.GetString("username"),
			password: cred.GetString("password"),
		}
		handler.credentials = append(handler.credentials, repoCred)
	}

	return &handler
}

// HandleRequest adds auth to a goproxy request
func (h *GoProxyServerHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	// Try OIDC credentials first
	if h.oidcRegistry.TryAuth(req, ctx) {
		return req, nil
	}

	// Fall back to static credentials
	for _, cred := range h.credentials {
		if !helpers.UrlMatchesRequest(req, cred.url, true) && !helpers.CheckHost(req, cred.host) {
			continue
		}

		logging.RequestLogf(ctx, "* authenticating goproxy request (host: %s)", req.URL.Hostname())
		req.SetBasicAuth(cred.username, cred.password)

		return req, nil
	}

	return req, nil
}
