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

// NPMRegistryHandler handles requests to NPM registries, adding auth to
// requests to registries for which we have credentials.
type NPMRegistryHandler struct {
	credentials  []npmRegistryCredentials
	oidcRegistry *oidc.OIDCRegistry
}

type npmRegistryCredentials struct {
	registry  string
	token     string
	host      string
	username  string
	password  string
	proxyOnly bool
}

// NewNPMRegistryHandler returns a new NPMRegistryHandler,
func NewNPMRegistryHandler(creds config.Credentials, client *http.Client) *NPMRegistryHandler {
	handler := NPMRegistryHandler{
		credentials:  []npmRegistryCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(client),
	}

	for _, cred := range creds {
		if cred["type"] != "npm_registry" {
			continue
		}

		registry := cred.GetString("registry")
		if registry == "" {
			registry = cred.GetString("url")
		}

		proxyOnly := cred.GetBool("proxy-only")
		if !proxyOnly {
			// OIDC credentials are not used as static credentials.
			if oidcCred, _, _ := handler.oidcRegistry.Register(cred, []string{"registry", "url"}, "npm registry"); oidcCred != nil {
				continue
			}
		}
		if proxyOnly && cred.GetString("token") == "" && cred.GetString("password") == "" {
			continue
		}

		npmCred := npmRegistryCredentials{
			registry:  registry,
			token:     cred.GetString("token"),
			host:      cred.Host(),
			username:  cred.GetString("username"),
			password:  cred.GetString("password"),
			proxyOnly: proxyOnly,
		}
		handler.credentials = append(handler.credentials, npmCred)
	}

	return &handler
}

// HandleRequest adds auth to an npm registry request
func (h *NPMRegistryHandler) HandleRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
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

func (h *NPMRegistryHandler) authenticateStaticCredential(
	req *http.Request,
	proxyCtx *goproxy.ProxyCtx,
	proxyOnly bool,
) bool {
	for _, cred := range h.credentials {
		if cred.proxyOnly != proxyOnly {
			continue
		}
		if !npmCredentialMatchesRequest(req, cred) {
			continue
		}

		if cred.token == "" && cred.password != "" {
			cred.token = cred.username + ":" + cred.password
		}

		username, password, found := strings.Cut(cred.token, ":")
		if found {
			logging.RequestLogf(proxyCtx, "* authenticating npm registry request (host: %s, basic auth)", helpers.GetHost(req))
			helpers.SetBasicAuthorization(req, username, password)
		} else {
			logging.RequestLogf(proxyCtx, "* authenticating npm registry request (host: %s, token auth)", helpers.GetHost(req))
			helpers.SetBearerAuthorization(req, cred.token)
		}
		return true
	}

	return false
}

func npmCredentialMatchesRequest(req *http.Request, cred npmRegistryCredentials) bool {
	matchURL := cred.registry
	if matchURL == "" {
		matchURL = cred.host
	}
	if helpers.CredentialURLMatchesRequest(req, matchURL, true) {
		return true
	}

	regURL, err := helpers.ParseURLLax(matchURL)
	if err != nil || helpers.AreHostnamesEqual(regURL.Hostname(), req.URL.Hostname()) ||
		!npmRegistryHostMatches(regURL.Hostname(), req.URL.Hostname()) {
		return false
	}

	regPort := regURL.Port()
	if regPort == "" {
		regPort = "443"
	}
	reqPort := req.URL.Port()
	if reqPort == "" {
		reqPort = "443"
	}
	return regPort == reqPort && helpers.PathMatches(req.URL.EscapedPath(), regURL.EscapedPath())
}

func npmRegistryHostMatches(regHost, reqHost string) bool {
	if helpers.AreHostnamesEqual(regHost, reqHost) {
		return true
	}

	// When using yarn, the yarn registry is used in place of the npm registry,
	// proxying to the npm registry where necessary. This is a special case in
	// which we share credentials across two hosts.
	//
	// We could use areHostnamesEqual here, but that likely isn't necessary
	// because it was added to better support private registries with custom
	// domains.
	if strings.EqualFold(regHost, "registry.npmjs.org") &&
		strings.EqualFold(reqHost, "registry.yarnpkg.com") {
		return true
	}

	return false
}
