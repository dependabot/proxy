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
	host      string
	url       string
	token     string
	proxyOnly bool
}

// NewRubyGemsServerHandler returns a new RubyGemsServerHandler.
func NewRubyGemsServerHandler(creds config.Credentials, client *http.Client) *RubyGemsServerHandler {
	handler := RubyGemsServerHandler{
		credentials:  []rubyGemsServerCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(client),
	}

	for _, cred := range creds {
		if cred["type"] != "rubygems_server" {
			continue
		}

		host := cred.Host()
		url := cred.GetString("url")

		proxyOnly := cred.GetBool("proxy-only")
		if !proxyOnly {
			// OIDC credentials are not used as static credentials.
			if oidcCred, _, _ := handler.oidcRegistry.Register(cred, []string{"url"}, "rubygems server"); oidcCred != nil {
				continue
			}
		}
		if proxyOnly && cred.GetString("token") == "" {
			continue
		}

		serverCred := rubyGemsServerCredentials{
			host:      host,
			url:       url,
			token:     cred.GetString("token"),
			proxyOnly: proxyOnly,
		}
		handler.credentials = append(handler.credentials, serverCred)
	}

	return &handler
}

// HandleRequest adds auth to a rubygems server request
func (h *RubyGemsServerHandler) HandleRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	oidcCredential := h.oidcRegistry.CredentialForRequest(req)
	if h.oidcRegistry.TryAuthCredential(req, proxyCtx, oidcCredential) {
		return req, nil
	}
	if h.authenticateStaticCredential(req, proxyCtx, false) {
		return req, nil
	}
	if hasUsableAuthorization(req) {
		return req, nil
	}
	if oidcCredential != nil {
		return req, nil
	}
	if !proxyOnlyCredentialRequestAllowed(req) {
		return req, nil
	}
	h.authenticateStaticCredential(req, proxyCtx, true)

	return req, nil
}

func (h *RubyGemsServerHandler) authenticateStaticCredential(
	req *http.Request,
	proxyCtx *goproxy.ProxyCtx,
	proxyOnly bool,
) bool {
	for _, cred := range h.credentials {
		if cred.proxyOnly != proxyOnly {
			continue
		}
		matchURL := cred.url
		if matchURL == "" {
			matchURL = cred.host
		}
		if !helpers.CredentialURLMatchesRequest(req, matchURL, true) {
			continue
		}

		logging.RequestLogf(proxyCtx, "* authenticating rubygems server request (host: %s)", req.URL.Hostname())
		username, password, _ := strings.Cut(cred.token, ":")
		helpers.SetBasicAuthorization(req, username, password)
		return true
	}

	return false
}
