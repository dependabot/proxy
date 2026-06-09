package handlers

import (
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/ctxdata"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

const pythonIndexResponseAuthKey = "python-index-response-auth"

type pythonIndexAuth struct {
	oidc     *oidc.OIDCCredential
	basic    pythonIndexCredentials
	hasBasic bool
}

type pythonIndexResponseAuth struct {
	auth    pythonIndexAuth
	baseURL url.URL
}

type pythonIndexDownloadAuthStore struct {
	mutex   sync.RWMutex
	entries []pythonIndexDownloadAuthEntry
}

type pythonIndexDownloadAuthEntry struct {
	prefix *url.URL
	auth   pythonIndexAuth
}

func newPythonIndexDownloadAuthStore() *pythonIndexDownloadAuthStore {
	return &pythonIndexDownloadAuthStore{}
}

func (s *pythonIndexDownloadAuthStore) add(prefix *url.URL, auth pythonIndexAuth) {
	if prefix == nil {
		return
	}

	normalized := normalizedPythonIndexDownloadURL(prefix)
	if normalized == nil {
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	for i := range s.entries {
		if sameOrigin(s.entries[i].prefix, normalized) && s.entries[i].prefix.Path == normalized.Path {
			return
		}
	}

	s.entries = append(s.entries, pythonIndexDownloadAuthEntry{
		prefix: normalized,
		auth:   auth,
	})
}

func (s *pythonIndexDownloadAuthStore) authFor(req *http.Request) (pythonIndexAuth, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var matched pythonIndexAuth
	bestPathLen := -1
	for _, entry := range s.entries {
		if !sameOrigin(entry.prefix, req.URL) || !isPathPrefix(entry.prefix.Path, req.URL.Path) {
			continue
		}
		if len(entry.prefix.Path) > bestPathLen {
			matched = entry.auth
			bestPathLen = len(entry.prefix.Path)
		}
	}

	if bestPathLen < 0 {
		return pythonIndexAuth{}, false
	}
	return matched, true
}

func (h *PythonIndexHandler) applyAuth(req *http.Request, ctx *goproxy.ProxyCtx, auth pythonIndexAuth) bool {
	if auth.oidc != nil {
		return h.oidcRegistry.TryAuthCredential(req, ctx, auth.oidc)
	}
	if !auth.hasBasic {
		return false
	}

	logging.RequestLogf(ctx, "* authenticating python index request (host: %s)", req.URL.Hostname())

	token := auth.basic.token
	if token == "" && auth.basic.password != "" {
		token = auth.basic.username + ":" + auth.basic.password
	}
	// ignore `found` because it's okay for the password to be an empty string
	username, password, _ := strings.Cut(token, ":")
	helpers.SetBasicAuthorization(req, username, password)

	return true
}

func rememberPythonIndexResponseAuth(ctx *goproxy.ProxyCtx, baseURL *url.URL, auth pythonIndexAuth) {
	if ctx == nil || baseURL == nil {
		return
	}

	ctxdata.SetValue(ctx, pythonIndexResponseAuthKey, pythonIndexResponseAuth{
		auth:    auth,
		baseURL: *baseURL,
	})
}

func pythonIndexResponseAuthFromContext(ctx *goproxy.ProxyCtx) (pythonIndexResponseAuth, bool) {
	if ctx == nil {
		return pythonIndexResponseAuth{}, false
	}

	value, ok := ctxdata.GetValue(ctx, pythonIndexResponseAuthKey)
	if !ok {
		return pythonIndexResponseAuth{}, false
	}

	responseAuth, ok := value.(pythonIndexResponseAuth)
	return responseAuth, ok
}
