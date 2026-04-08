package handlers

import (
	"net/http"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

// MavenRepositoryHandler handles requests to maven repositories, adding auth.
type MavenRepositoryHandler struct {
	credentials  []mavenRepositoryCredentials
	oidcRegistry *oidc.OIDCRegistry
}

type mavenRepositoryCredentials struct {
	url      string
	host     string
	username string
	password string
}

// NewMavenRepositoryHandler returns a new MavenRepositoryHandler.
func NewMavenRepositoryHandler(creds config.Credentials) *MavenRepositoryHandler {
	handler := MavenRepositoryHandler{
		credentials:  []mavenRepositoryCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(),
	}

	for _, cred := range creds {
		if cred["type"] != "maven_repository" {
			continue
		}

		url := cred.GetString("url")

		// OIDC credentials are not used as static credentials.
		if oidcCred, _, _ := handler.oidcRegistry.Register(cred, []string{"url"}, "maven repository"); oidcCred != nil {
			continue
		}

		username := cred.GetString("username")
		password := cred.GetString("password")
		if username == "" && password == "" {
			continue
		}

		repoCred := mavenRepositoryCredentials{
			url:      url,
			host:     cred.GetString("host"),
			username: username,
			password: password,
		}
		handler.credentials = append(handler.credentials, repoCred)
	}

	return &handler
}

// HandleRequest adds auth to a maven repository request
func (h *MavenRepositoryHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if (req.URL.Scheme != "http" && req.URL.Scheme != "https") || !helpers.MethodPermitted(req, "GET", "HEAD") {
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

		logging.RequestLogf(ctx, "* authenticating maven repository request (host: %s)", req.URL.Hostname())
		req.SetBasicAuth(cred.username, cred.password)

		return req, nil
	}

	return req, nil
}
