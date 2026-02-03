package handlers

import (
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

// PythonIndexHandler handles requests to Python indexes, adding auth.
type PythonIndexHandler struct {
	credentials     []pythonIndexCredentials
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
}

type pythonIndexCredentials struct {
	indexURL string
	token    string
	host     string
	username string
	password string
}

// NewPythonIndexHandler returns a new PythonIndexHandler.
func NewPythonIndexHandler(creds config.Credentials) *PythonIndexHandler {
	handler := PythonIndexHandler{
		credentials:     []pythonIndexCredentials{},
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
	}

	for _, cred := range creds {
		if cred["type"] != "python_index" {
			continue
		}

		indexURL := cred.GetString("index-url")

		oidcCredential, _ := oidc.CreateOIDCCredential(cred)
		if oidcCredential != nil {
			host := cred.Host()
			if host == "" && indexURL != "" {
				regURL, err := helpers.ParseURLLax(indexURL)
				if err == nil {
					host = regURL.Hostname()
				}
			}
			if host != "" {
				handler.oidcCredentials[host] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for python index: %s", oidcCredential.Provider(), host)
			}
			continue
		}

		indexCred := pythonIndexCredentials{
			indexURL: indexURL,
			token:    cred.GetString("token"),
			host:     cred.GetString("host"),
			username: cred.GetString("username"),
			password: cred.GetString("password"),
		}
		// fallback to URL for simplicity in UI configuration
		if indexCred.indexURL == "" {
			indexCred.indexURL = cred.GetString("url")
		}
		handler.credentials = append(handler.credentials, indexCred)
	}

	return &handler
}

// HandleRequest adds auth to a python index request
func (h *PythonIndexHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	// Try OIDC credentials first
	if oidc.TryAuthOIDCRequestWithPrefix(&h.mutex, h.oidcCredentials, req, ctx) {
		return req, nil
	}

	// Fall back to static credentials
	for _, cred := range h.credentials {
		re, _ := regexp.Compile(`/\+?simple/?\z`)
		indexURL := re.ReplaceAllString(cred.indexURL, "/")
		if !(helpers.UrlMatchesRequest(req, indexURL, true) || helpers.CheckHost(req, cred.host)) {
			continue
		}

		logging.RequestLogf(ctx, "* authenticating python index request (host: %s)", req.URL.Hostname())

		token := cred.token
		if token == "" && cred.password != "" {
			token = cred.username + ":" + cred.password
		}
		// ignore `found` because it's okay for the password to be an empty string
		username, password, _ := strings.Cut(token, ":")
		req.SetBasicAuth(username, password)

		return req, nil
	}

	return req, nil
}
