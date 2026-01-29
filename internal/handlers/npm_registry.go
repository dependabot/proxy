package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
	"github.com/elazarl/goproxy"
)

// NPMRegistryHandler handles requests to NPM registries, adding auth to
// requests to registries for which we have credentials.
type NPMRegistryHandler struct {
	credentials     []npmRegistryCredentials
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
}

type npmRegistryCredentials struct {
	registry string
	token    string
	host     string
	username string
	password string
}

// NewNPMRegistryHandler returns a new NPMRegistryHandler,
func NewNPMRegistryHandler(creds config.Credentials) *NPMRegistryHandler {
	handler := NPMRegistryHandler{
		credentials:     []npmRegistryCredentials{},
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
	}

	for _, cred := range creds {
		if cred["type"] != "npm_registry" {
			continue
		}

		registry := cred.GetString("registry")

		oidcCredential, _ := oidc.CreateOIDCCredential(cred)
		if oidcCredential != nil {
			host := cred.Host()
			if host == "" && registry != "" {
				regURL, err := helpers.ParseURLLax(registry)
				if err == nil {
					host = regURL.Hostname()
				}
			}
			if host != "" {
				handler.oidcCredentials[host] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for npm registry: %s", oidcCredential.Provider(), host)
			}
			continue
		}

		npmCred := npmRegistryCredentials{
			registry: registry,
			token:    cred.GetString("token"),
			host:     cred.Host(),
			username: cred.GetString("username"),
			password: cred.GetString("password"),
		}
		handler.credentials = append(handler.credentials, npmCred)
	}

	return &handler
}

// HandleRequest adds auth to an npm registry request
func (h *NPMRegistryHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	reqHost := helpers.GetHost(req)
	reqPort := req.URL.Port()
	if reqPort == "" {
		reqPort = "443"
	}

	// Try OIDC credentials first
	h.mutex.RLock()
	oidcCred, hasOIDC := h.oidcCredentials[reqHost]
	h.mutex.RUnlock()

	if hasOIDC {
		token, err := oidc.GetOrRefreshOIDCToken(oidcCred, req.Context())
		if err != nil {
			logging.RequestLogf(ctx, "* failed to get token via OIDC for %s: %v", reqHost, err)
			// Fall through to try static credentials
		} else {
			logging.RequestLogf(ctx, "* authenticating npm registry request with OIDC token (host: %s)", reqHost)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			return req, nil
		}
	}

	// Fall back to static credentials
	for _, cred := range h.credentials {
		regURL, err := helpers.ParseURLLax(cred.registry)
		if err != nil {
			continue
		}

		host := cred.host
		if host == "" {
			host = regURL.Hostname()
		}

		if !npmRegistryHostMatches(host, reqHost) {
			continue
		}

		regPort := regURL.Port()
		if regPort == "" {
			regPort = "443"
		}

		if regPort != reqPort {
			continue
		}

		if cred.token == "" && cred.password != "" {
			cred.token = cred.username + ":" + cred.password
		}

		username, password, found := strings.Cut(cred.token, ":")
		if found {
			logging.RequestLogf(ctx, "* authenticating npm registry request (host: %s, basic auth)", reqHost)
			req.SetBasicAuth(username, password)
		} else {
			logging.RequestLogf(ctx, "* authenticating npm registry request (host: %s, token auth)", reqHost)
			req.Header.Set("authorization", "Bearer "+cred.token)
		}
		return req, nil
	}

	return req, nil
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
	if regHost == "registry.npmjs.org" && reqHost == "registry.yarnpkg.com" {
		return true
	}

	return false
}
