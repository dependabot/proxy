package handlers

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
	"github.com/dependabot/proxy/internal/proxyctx"
)

const nugetDiscoveryCtxKey = "nuget.discovery-auth"

type nugetV2IndexResponse struct {
	Base string `xml:"base,attr"`
}

type nugetV3IndexResource struct {
	ID   string `json:"@id"`
	Type string `json:"@type"`
}

type nugetV3IndexResponse struct {
	Version  string                 `json:"version"`
	Resource []nugetV3IndexResource `json:"resources"`
}

// NugetFeedHandler handles requests to nuget feeds, adding auth.
type NugetFeedHandler struct {
	credentials         []nugetFeedCredentials
	credentialURLs      map[string]struct{}
	credentialsMutex    sync.RWMutex
	discoverySources    []nugetDiscoveryAuth
	discoverySourceURLs map[string]struct{}
	discoveryMutex      sync.RWMutex
	oidcRegistry        *oidc.OIDCRegistry
}

type nugetFeedCredentials struct {
	url      string
	host     string
	token    string
	username string
	password string
}

type nugetDiscoveryAuth struct {
	serviceIndexURL      string
	static               nugetFeedCredentials
	oidc                 *oidc.OIDCCredential
	registerRedirectAuth bool
}

// NewNugetFeedHandler returns a new NugetFeedHandler.
func NewNugetFeedHandler(creds config.Credentials, client *http.Client) *NugetFeedHandler {
	handler := NugetFeedHandler{
		credentials:         []nugetFeedCredentials{},
		credentialURLs:      make(map[string]struct{}),
		discoverySourceURLs: make(map[string]struct{}),
		oidcRegistry:        oidc.NewOIDCRegistry(client),
	}

	for _, cred := range creds {
		if cred["type"] != "nuget_feed" {
			continue
		}

		url := cred.GetString("url")
		// host is only ever sent from the cli, not dependabot.yml
		host := strings.ToLower(cred.GetString("host"))
		token := cred.GetString("token")
		username := cred.GetString("username")
		password := cred.GetString("password")

		oidcCredential, _, ok := handler.oidcRegistry.Register(cred, []string{"url"}, "nuget feed")
		if ok {
			if url != "" {
				handler.addDiscoverySource(nugetDiscoveryAuth{
					serviceIndexURL:      url,
					oidc:                 oidcCredential,
					registerRedirectAuth: true,
				})
			}
			continue
		}
		// OIDC credentials are not used as static credentials.
		if oidcCredential != nil {
			continue
		}

		feedCred := nugetFeedCredentials{
			url:      url,
			host:     host,
			token:    token,
			username: username,
			password: password,
		}
		handler.addStaticCredential(feedCred)
		if url != "" && (token != "" || password != "") {
			handler.addDiscoverySource(nugetDiscoveryAuth{
				serviceIndexURL:      url,
				static:               feedCred,
				registerRedirectAuth: true,
			})
		}
	}

	return &handler
}

func extraUrlsFromSourceResponse(body []byte, url string) []string {
	var urls []string
	bodyString := strings.TrimSpace(string(body))
	if bodyString == "" {
		logging.RequestLogf(nil, "empty API response from NuGet feed %s", url)
		return nil
	}
	bodyReader := bytes.NewReader(body)
	switch {
	case strings.HasPrefix(bodyString, "<"):
		// XML v2 API
		urls = handleV2Response(bodyReader, url)
	case strings.HasPrefix(bodyString, "{"):
		// JSON v3 API
		urls = handleV3Response(bodyReader, url)
	default:
		logging.RequestLogf(nil, "unknown API response: %.10s...", bodyString)
	}

	var result []string
	for _, url := range urls {
		if url != "" {
			result = append(result, url)
		}
	}

	return result
}

func handleV2Response(body io.Reader, url string) (v2Urls []string) {
	var response nugetV2IndexResponse
	err := xml.NewDecoder(body).Decode(&response)
	if err != nil {
		logging.RequestLogf(nil, "error unmarshalling xml response (%s): %v", url, err)
		return
	}

	if url != response.Base {
		v2Urls = append(v2Urls, response.Base)
	}

	return
}

func handleV3Response(body io.Reader, url string) (v3Urls []string) {
	var rsp nugetV3IndexResponse
	dec := json.NewDecoder(body)
	if err := dec.Decode(&rsp); err != nil {
		logging.RequestLogf(nil, "error unmarshalling json response (%s): %v", url, err)
		return
	}

	for _, resource := range rsp.Resource {
		// some resource types have a trailing slash and version number, but since the version numbers will always be updating, we trim them off and authenticate all of them
		slashIndex := strings.Index(resource.Type, "/")
		if slashIndex < 0 {
			slashIndex = len(resource.Type)
		}

		trimmedResourceType := resource.Type[0:slashIndex]

		// "*Template" URLs aren't a simple prefix, they have find-and-replace semantics that aren't relevant for regular feed consumption
		// See the complete list of resource types at https://learn.microsoft.com/en-us/nuget/api/overview#resources-and-schema
		if strings.HasSuffix(trimmedResourceType, "Template") {
			continue
		}

		v3Urls = append(v3Urls, resource.ID)
	}

	return
}

// PrepareRequest marks configured service-index requests for response-time
// discovery. It is registered before the cache handler so cached indexes can
// teach the same resource routes as live responses.
func (h *NugetFeedHandler) PrepareRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if proxyCtx == nil || req.Method != http.MethodGet || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
		return req, nil
	}

	h.discoveryMutex.RLock()
	defer h.discoveryMutex.RUnlock()
	for _, source := range h.discoverySources {
		if source.oidc != nil && req.URL.Scheme != "https" {
			continue
		}
		if isNugetServiceIndexRequest(req, source.serviceIndexURL) {
			matchedSource := source
			matchedSource.serviceIndexURL = req.URL.String()
			markNugetDiscovery(proxyCtx, matchedSource)
			return req, nil
		}
	}

	return req, nil
}

// HandleRequest adds auth to a NuGet feed request.
func (h *NugetFeedHandler) HandleRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if (req.URL.Scheme != "http" && req.URL.Scheme != "https") || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	// Try OIDC credentials first (HTTPS only to avoid leaking tokens over plaintext)
	if req.URL.Scheme == "https" {
		oidcCredential := h.oidcRegistry.CredentialForRequest(req)
		if h.oidcRegistry.TryAuthCredential(req, proxyCtx, oidcCredential) {
			return req, nil
		}
	}

	// Prefer the most specific URL credential, with host-only credentials as
	// fallback. This avoids a broad credential shadowing a narrower feed.
	h.credentialsMutex.RLock()
	defer h.credentialsMutex.RUnlock()
	var urlCredential *nugetFeedCredentials
	var hostCredential *nugetFeedCredentials
	bestPathLength := -1
	for i := range h.credentials {
		cred := &h.credentials[i]
		if cred.token == "" && cred.password == "" {
			continue
		}
		if helpers.UrlMatchesRequest(req, cred.url, true) {
			parsedURL, err := helpers.ParseURLLax(cred.url)
			if err == nil && len(parsedURL.Path) > bestPathLength {
				urlCredential = cred
				bestPathLength = len(parsedURL.Path)
			}
		}
		if hostCredential == nil && helpers.CheckHost(req, cred.host) {
			hostCredential = cred
		}
	}
	if urlCredential != nil {
		authenticateNugetRequest(req, *urlCredential, proxyCtx)
		return req, nil
	}
	if hostCredential != nil {
		authenticateNugetRequest(req, *hostCredential, proxyCtx)
	}

	return req, nil
}

func (h *NugetFeedHandler) HandleResponse(resp *http.Response, proxyCtx *goproxy.ProxyCtx) *http.Response {
	if resp == nil {
		return resp
	}

	discoveryAuth, ok := nugetDiscoveryAuthFromContext(proxyCtx)
	if !ok {
		return resp
	}
	if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		h.registerServiceIndexRedirect(resp, discoveryAuth, proxyCtx)
		return resp
	}
	if resp.Body == nil || resp.Body == http.NoBody || resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusResetContent || resp.StatusCode < http.StatusOK ||
		resp.StatusCode >= http.StatusMultipleChoices {
		return resp
	}

	originalBody := resp.Body
	body, err := io.ReadAll(originalBody)
	resp.Body = &replayReadCloser{
		Reader: io.MultiReader(bytes.NewReader(body), originalBody),
		Closer: originalBody,
	}
	if err != nil {
		return resp
	}

	for _, discoveredURL := range extraUrlsFromSourceResponse(body, discoveryAuth.serviceIndexURL) {
		if discoveryAuth.oidc != nil {
			h.oidcRegistry.RegisterURL(discoveredURL, discoveryAuth.oidc, "nuget resource")
			continue
		}

		credential := discoveryAuth.static
		credential.url = discoveredURL
		credential.host = ""
		if h.addStaticCredential(credential) {
			logging.RequestLogf(proxyCtx, "  added url to authentication list: %s", discoveredURL)
		}
	}

	return resp
}

func (h *NugetFeedHandler) registerServiceIndexRedirect(resp *http.Response, source nugetDiscoveryAuth, proxyCtx *goproxy.ProxyCtx) {
	location := resp.Header.Get("Location")
	if location == "" {
		return
	}
	baseURL, err := url.Parse(source.serviceIndexURL)
	if err != nil {
		return
	}
	locationURL, err := url.Parse(location)
	if err != nil {
		return
	}
	redirectURL := baseURL.ResolveReference(locationURL)
	if redirectURL.User != nil || (redirectURL.Scheme != "http" && redirectURL.Scheme != "https") {
		return
	}
	if source.oidc != nil && redirectURL.Scheme != "https" {
		return
	}

	redirectedSource := source
	redirectedSource.serviceIndexURL = redirectURL.String()
	redirectedSource.registerRedirectAuth = source.registerRedirectAuth && sameOrigin(baseURL, redirectURL)
	if !h.addDiscoverySource(redirectedSource) {
		return
	}

	if redirectedSource.registerRedirectAuth {
		if source.oidc != nil {
			h.oidcRegistry.RegisterURL(redirectURL.String(), source.oidc, "nuget service-index redirect")
		} else {
			credential := source.static
			credential.url = redirectURL.String()
			credential.host = ""
			h.addStaticCredential(credential)
		}
	}
	logging.RequestLogf(proxyCtx, "  registered nuget service-index redirect: %s", redirectURL.String())
}

func (h *NugetFeedHandler) addStaticCredential(credential nugetFeedCredentials) bool {
	if credential.token == "" && credential.password == "" {
		return false
	}

	h.credentialsMutex.Lock()
	defer h.credentialsMutex.Unlock()

	if credential.url != "" {
		key := nugetCredentialURLKey(credential.url)
		if _, ok := h.credentialURLs[key]; ok {
			logging.RequestLogf(nil, "skipping duplicate NuGet credential URL because it is already registered: %s", credential.url)
			return false
		}
		h.credentialURLs[key] = struct{}{}
	}
	h.credentials = append(h.credentials, credential)
	return true
}

func (h *NugetFeedHandler) addDiscoverySource(source nugetDiscoveryAuth) bool {
	h.discoveryMutex.Lock()
	defer h.discoveryMutex.Unlock()

	key := nugetDiscoverySourceKey(source.serviceIndexURL)
	if _, ok := h.discoverySourceURLs[key]; ok {
		return false
	}
	h.discoverySourceURLs[key] = struct{}{}
	h.discoverySources = append(h.discoverySources, source)
	logging.RequestLogf(nil, "registered NuGet service index for deferred discovery: %s", source.serviceIndexURL)
	return true
}

func markNugetDiscovery(proxyCtx *goproxy.ProxyCtx, auth nugetDiscoveryAuth) {
	if proxyCtx != nil {
		proxyctx.SetValue(proxyCtx, nugetDiscoveryCtxKey, auth)
	}
}

func nugetDiscoveryAuthFromContext(proxyCtx *goproxy.ProxyCtx) (nugetDiscoveryAuth, bool) {
	if proxyCtx == nil {
		return nugetDiscoveryAuth{}, false
	}
	value, ok := proxyctx.GetValue(proxyCtx, nugetDiscoveryCtxKey)
	if !ok {
		return nugetDiscoveryAuth{}, false
	}
	auth, ok := value.(nugetDiscoveryAuth)
	return auth, ok
}

func isNugetServiceIndexRequest(req *http.Request, sourceURL string) bool {
	if req.Method != http.MethodGet {
		return false
	}
	parsedURL, err := helpers.ParseURLLax(sourceURL)
	if err != nil || !helpers.UrlMatchesRequest(req, sourceURL, true) {
		return false
	}
	if parsedURL.Scheme != "" && !strings.EqualFold(parsedURL.Scheme, req.URL.Scheme) {
		return false
	}
	return strings.TrimRight(parsedURL.Path, "/") == strings.TrimRight(req.URL.Path, "/") &&
		parsedURL.RawQuery == req.URL.RawQuery
}

func nugetCredentialURLKey(rawURL string) string {
	parsedURL, err := helpers.ParseURLLax(rawURL)
	if err != nil {
		return rawURL
	}
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}
	return strings.ToLower(parsedURL.Hostname()) + ":" + port + strings.TrimRight(parsedURL.Path, "/") + "?" + parsedURL.RawQuery
}

// Discovery matching distinguishes explicit schemes, while static credential
// matching intentionally remains scheme-agnostic for backwards compatibility.
func nugetDiscoverySourceKey(rawURL string) string {
	parsedURL, err := helpers.ParseURLLax(rawURL)
	if err != nil {
		return rawURL
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme == "" {
		scheme = "*"
	}
	return scheme + "|" + nugetCredentialURLKey(rawURL)
}

func authenticateNugetRequest(req *http.Request, cred nugetFeedCredentials, proxyCtx *goproxy.ProxyCtx) {
	token := cred.token
	if token == "" && cred.password != "" {
		token = cred.username + ":" + cred.password
	}
	username, password, found := strings.Cut(token, ":")
	if found {
		logging.RequestLogf(proxyCtx, "* authenticating nuget feed request (host: %s, basic auth)", req.URL.Hostname())
		helpers.SetBasicAuthorization(req, username, password)
	} else if token != "" {
		if shouldTreatTokenAsPassword(req.URL) {
			logging.RequestLogf(proxyCtx, "* authenticating nuget feed request (host: %s, basic auth for Azure DevOps)", req.URL.Hostname())
			helpers.SetBasicAuthorization(req, "", token)
		} else {
			logging.RequestLogf(proxyCtx, "* authenticating nuget feed request (host: %s, bearer auth)", req.URL.Hostname())
			helpers.SetBearerAuthorization(req, token)
		}
	}
}

func shouldTreatTokenAsPassword(url *url.URL) bool {
	if url.Hostname() == "pkgs.dev.azure.com" {
		return true
	}
	return strings.HasSuffix(url.Hostname(), ".pkgs.visualstudio.com") && strings.Contains(url.Path, "/_packaging/")
}
