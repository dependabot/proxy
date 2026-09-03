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
	url       string
	host      string
	username  string
	password  string
	proxyOnly bool
}

// NewMavenRepositoryHandler returns a new MavenRepositoryHandler.
func NewMavenRepositoryHandler(creds config.Credentials, client *http.Client) *MavenRepositoryHandler {
	handler := MavenRepositoryHandler{
		credentials:  []mavenRepositoryCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(client),
	}

	for _, cred := range creds {
		if cred["type"] != "maven_repository" {
			continue
		}

		url := cred.GetString("url")

		proxyOnly := cred.GetBool("proxy-only")
		if !proxyOnly {
			// OIDC credentials are not used as static credentials.
			if oidcCred, _, _ := handler.oidcRegistry.Register(cred, []string{"url"}, "maven repository"); oidcCred != nil {
				continue
			}
		}

		username := cred.GetString("username")
		password := cred.GetString("password")
		if username == "" && password == "" {
			continue
		}

		repoCred := mavenRepositoryCredentials{
			url:       url,
			host:      cred.GetString("host"),
			username:  username,
			password:  password,
			proxyOnly: proxyOnly,
		}
		handler.credentials = append(handler.credentials, repoCred)
	}

	return &handler
}

// HandleRequest adds auth to a maven repository request
func (h *MavenRepositoryHandler) HandleRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if (req.URL.Scheme != "http" && req.URL.Scheme != "https") || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	var oidcCredential *oidc.OIDCCredential
	if req.URL.Scheme == "https" {
		oidcCredential = h.oidcRegistry.CredentialForRequest(req)
		if h.oidcRegistry.TryAuthCredential(req, proxyCtx, oidcCredential) {
			return req, nil
		}
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

func (h *MavenRepositoryHandler) authenticateStaticCredential(
	req *http.Request,
	proxyCtx *goproxy.ProxyCtx,
	proxyOnly bool,
) bool {
	if proxyOnly && !proxyOnlyCredentialRequestAllowed(req) {
		return false
	}

	for _, cred := range h.credentials {
		if cred.proxyOnly != proxyOnly {
			continue
		}
		if !helpers.CredentialURLMatchesRequest(req, cred.url, true) &&
			!helpers.CheckHost(req, cred.host) {
			continue
		}

		logging.RequestLogf(proxyCtx, "* authenticating maven repository request (host: %s)", req.URL.Hostname())
		helpers.SetBasicAuthorization(req, cred.username, cred.password)
		return true
	}

	return false
}
