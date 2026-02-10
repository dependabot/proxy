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

// MavenRepositoryHandler handles requests to maven repositories, adding auth.
type MavenRepositoryHandler struct {
	credentials     []mavenRepositoryCredentials
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
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
		credentials:     []mavenRepositoryCredentials{},
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
	}

	for _, cred := range creds {
		if cred["type"] != "maven_repository" {
			continue
		}

		url := cred.GetString("url")

		oidcCredential, _ := oidc.CreateOIDCCredential(cred)
		if oidcCredential != nil {
			host := cred.Host()
			if host == "" && url != "" {
				regURL, err := helpers.ParseURLLax(url)
				if err == nil {
					host = regURL.Hostname()
				}
			}
			if host != "" {
				handler.oidcCredentials[host] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for maven repository: %s", oidcCredential.Provider(), host)
			}
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
	if oidc.TryAuthOIDCRequestWithPrefix(&h.mutex, h.oidcCredentials, req, ctx) {
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
