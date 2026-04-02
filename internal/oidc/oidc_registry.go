package oidc

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
)

// OIDCRegistry stores OIDC credentials indexed by host, with path-based
// matching within each host bucket. This structure provides O(1) host lookup
// and avoids key collisions when multiple registries share a host with
// different paths.
type OIDCRegistry struct {
	byHost map[string][]oidcEntry
	mutex  sync.RWMutex
}

type oidcEntry struct {
	path       string // URL path prefix, e.g. "/org/_packaging/feed-A/npm/registry"
	port       string // port, defaults to "443"
	credential *OIDCCredential
}

// NewOIDCRegistry creates an empty registry.
func NewOIDCRegistry() *OIDCRegistry {
	return &OIDCRegistry{
		byHost: make(map[string][]oidcEntry),
	}
}

// Register attempts to create an OIDC credential from the config and store it.
// urlFields are checked in order for a URL (preserving host + path);
// falls back to cred.Host() (hostname only) as last resort.
//
// Returns:
//   - (credential, key, true)  if an OIDC credential was created and registered
//   - (credential, "", false)  if OIDC-configured but no URL or host could be resolved
//   - (nil, "", false)         if the credential is not OIDC-configured
func (r *OIDCRegistry) Register(
	cred config.Credential,
	urlFields []string,
	registryType string,
) (*OIDCCredential, string, bool) {
	oidcCredential, _ := CreateOIDCCredential(cred)
	if oidcCredential == nil {
		return nil, "", false
	}

	// Resolve the key: prefer URL fields (preserves path), fall back to host
	var key string
	for _, field := range urlFields {
		if v := cred.GetString(field); v != "" {
			key = v
			break
		}
	}
	if key == "" {
		key = cred.Host()
	}
	if key == "" {
		return oidcCredential, "", false
	}

	r.addEntry(key, oidcCredential)
	logging.RequestLogf(nil, "registered %s OIDC credentials for %s: %s", oidcCredential.Provider(), registryType, key)

	return oidcCredential, key, true
}

// RegisterURL adds an already-created credential under a URL.
// Used by nuget to register HTTP-discovered resource URLs that
// should share the same OIDC credential as the primary feed URL.
func (r *OIDCRegistry) RegisterURL(url string, cred *OIDCCredential, registryType string) {
	if url == "" || cred == nil {
		return
	}
	r.addEntry(url, cred)
	logging.RequestLogf(nil, "registered %s OIDC credentials for %s: %s", cred.Provider(), registryType, url)
}

// TryAuth finds the matching OIDC credential for the request and
// sets the appropriate auth header.
//
// Lookup:
//  1. Find the host bucket via map lookup (exact hostname match)
//  2. Within that bucket, find the entry whose stored path is a
//     prefix of the request path
//
// Returns true if the request was authenticated, false otherwise.
func (r *OIDCRegistry) TryAuth(req *http.Request, ctx *goproxy.ProxyCtx) bool {
	host := strings.ToLower(helpers.GetHost(req))
	reqPort := req.URL.Port()
	if reqPort == "" {
		reqPort = "443"
	}

	r.mutex.RLock()
	entries := r.byHost[host]
	r.mutex.RUnlock()

	if len(entries) == 0 {
		return false
	}

	// Find the most specific matching entry: host is already matched,
	// select the longest path prefix among entries with the same port.
	var matched *OIDCCredential
	bestPathLen := -1
	for i := range entries {
		e := &entries[i]
		if e.port != reqPort {
			continue
		}
		if !strings.HasPrefix(req.URL.Path, e.path) {
			continue
		}
		if len(e.path) > bestPathLen {
			matched = e.credential
			bestPathLen = len(e.path)
		}
	}

	if matched == nil {
		return false
	}

	token, err := GetOrRefreshOIDCToken(matched, req.Context())
	if err != nil {
		logging.RequestLogf(ctx, "* failed to get %s token via OIDC for %s: %v", matched.Provider(), host, err)
		return false
	}

	switch matched.parameters.(type) {
	case *CloudsmithOIDCParameters:
		logging.RequestLogf(ctx, "* authenticating request with OIDC API key (host: %s)", host)
		req.Header.Set("X-Api-Key", token)
	default:
		logging.RequestLogf(ctx, "* authenticating request with OIDC token (host: %s)", host)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	return true
}

// addEntry parses a URL or hostname string and adds a credential entry
// to the appropriate host bucket.
func (r *OIDCRegistry) addEntry(urlOrHost string, cred *OIDCCredential) {
	host, path, port := parseRegistryURL(urlOrHost)
	if host == "" {
		return
	}

	entry := oidcEntry{
		path:       path,
		port:       port,
		credential: cred,
	}

	r.mutex.Lock()
	r.byHost[host] = append(r.byHost[host], entry)
	r.mutex.Unlock()
}

// parseRegistryURL extracts host, path, and port from a URL or hostname string.
// For hostname-only input, path is empty and port defaults to "443".
func parseRegistryURL(urlOrHost string) (host, path, port string) {
	parsed, err := helpers.ParseURLLax(urlOrHost)
	if err != nil {
		return "", "", ""
	}

	host = strings.ToLower(parsed.Hostname())
	path = strings.TrimRight(parsed.Path, "/")
	port = parsed.Port()
	if port == "" {
		port = "443"
	}

	return host, path, port
}
