package handlers

import (
	"net/http"
	"regexp"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/oidc"
)

var simpleSuffixRe = regexp.MustCompile(`/\+?simple/?\z`)

// PythonIndexHandler handles requests to Python indexes, adding auth.
type PythonIndexHandler struct {
	credentials  []pythonIndexCredentials
	downloadAuth *pythonIndexDownloadAuthStore
	oidcRegistry *oidc.OIDCRegistry
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
		credentials:  []pythonIndexCredentials{},
		downloadAuth: newPythonIndexDownloadAuthStore(),
		oidcRegistry: oidc.NewOIDCRegistry(),
	}

	for _, cred := range creds {
		if cred["type"] != "python_index" {
			continue
		}

		indexURL := cred.GetString("index-url")

		oidcCredential, _ := oidc.CreateOIDCCredential(cred)
		if oidcCredential != nil {
			// Normalize the registration URL by stripping the /simple or /+simple
			// suffix, matching how static credentials are matched at request time.
			// Without this, a config of /dependabot/+simple/ would not prefix-match
			// requests to /dependabot/pkg/a.
			regURL := indexURL
			if regURL == "" {
				regURL = cred.GetString("url")
			}
			if regURL != "" {
				regURL = simpleSuffixRe.ReplaceAllString(regURL, "/")
			} else {
				regURL = cred.Host()
			}
			if regURL != "" {
				handler.oidcRegistry.RegisterURL(regURL, oidcCredential, "python index")
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

	if auth, ok := h.downloadAuth.authFor(req); ok && h.applyAuth(req, ctx, auth) {
		return req, nil
	}

	// Try OIDC credentials first
	if credential := h.oidcRegistry.CredentialForRequest(req); h.oidcRegistry.TryAuthCredential(req, ctx, credential) {
		rememberPythonIndexResponseAuth(ctx, req.URL, pythonIndexAuth{oidc: credential})
		return req, nil
	}

	// Fall back to static credentials
	for _, cred := range h.credentials {
		indexURL := simpleSuffixRe.ReplaceAllString(cred.indexURL, "/")
		// Apply credentials if:
		// 1. URL matches with path (e.g., /pypi/...), OR
		// 2. Host:port matches (regardless of path), OR
		// 3. Explicit host field matches
		if !helpers.UrlMatchesRequest(req, indexURL, true) && 
			!helpers.UrlMatchesRequest(req, indexURL, false) && 
			!helpers.CheckHost(req, cred.host) {
			continue
		}

		auth := pythonIndexAuth{basic: cred, hasBasic: true}
		h.applyAuth(req, ctx, auth)
		rememberPythonIndexResponseAuth(ctx, req.URL, auth)

		return req, nil
	}

	return req, nil
}
