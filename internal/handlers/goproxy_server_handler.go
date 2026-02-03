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

type GoProxyServerHandler struct {
	credentials     []goProxyServerCredentials
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
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
		credentials:     []goProxyServerCredentials{},
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
	}

	for _, cred := range creds {
		if cred["type"] != "goproxy_server" {
			continue
		}

		url := cred.GetString("url")
		host := cred.GetString("host")

		oidcCredential, _ := oidc.CreateOIDCCredential(cred)
		if oidcCredential != nil {
			urlOrHost := url
			if urlOrHost == "" {
				urlOrHost = host
			}
			if urlOrHost != "" {
				handler.oidcCredentials[urlOrHost] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for goproxy server: %s", oidcCredential.Provider(), urlOrHost)
			}
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
	if oidc.TryAuthOIDCRequestWithPrefix(&h.mutex, h.oidcCredentials, req, ctx) {
		return req, nil
	}

	// Fall back to static credentials
	for _, cred := range h.credentials {
		if !(helpers.UrlMatchesRequest(req, cred.url, true) || helpers.CheckHost(req, cred.host)) {
			continue
		}

		logging.RequestLogf(ctx, "* authenticating goproxy request (host: %s)", req.URL.Hostname())
		req.SetBasicAuth(cred.username, cred.password)

		return req, nil
	}

	return req, nil
}
