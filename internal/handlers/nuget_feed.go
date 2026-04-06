package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

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
	credentials  []nugetFeedCredentials
	oidcRegistry *oidc.OIDCRegistry
}

type nugetFeedCredentials struct {
	url      string
	host     string
	token    string
	username string
	password string
}

// NewNugetFeedHandler returns a new NugetFeedHandler.
func NewNugetFeedHandler(creds config.Credentials) *NugetFeedHandler {
	handler := NugetFeedHandler{
		credentials:  []nugetFeedCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(),
	}

	httpClient := &http.Client{
		Timeout: time.Second * 10,
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
			// Discover additional resource URLs from the nuget feed index.
			// Host-only credentials (from the CLI) are still registered above
			// for request-time matching, but discovery requires an absolute URL.
			// Wrapped in a closure so defer runs promptly for each credential,
			// ensuring the HTTP response body is always closed (pre-existing
			// leak fixed here: the body was previously leaked on ReadAll error
			// and on early-return status code paths).
			if url != "" {
				func() {
					req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
					if err != nil {
						logging.RequestLogf(nil, "error creating http request (%s): %v", url, err)
						return
					}

					if req.URL.Scheme != "https" {
						logging.RequestLogf(nil, "refusing to discover nuget feed over non-https URL %s", url)
						return
					}

					if !handler.oidcRegistry.TryAuth(req, nil) {
						return
					}

					rawRsp, err := httpClient.Do(req)
					if err != nil {
						logging.RequestLogf(nil, "error retrieving http response (%s): %v", url, err)
						return
					}
					defer rawRsp.Body.Close()

					body, err := io.ReadAll(rawRsp.Body)
					if err != nil {
						logging.RequestLogf(nil, "error reading http response body (%s): %v", url, err)
						return
					}

					switch rawRsp.StatusCode {
					case 401, 403:
						logging.RequestLogf(nil, "unauthorized for nuget feed %s", url)
						return
					}

					if rawRsp.StatusCode >= 400 {
						logging.RequestLogf(nil, "unexpected http response %d for nuget feed %s", rawRsp.StatusCode, url)
						return
					}

					urlsToAuthenticate := extraUrlsFromSourceResponse(body, url)
					for _, discoveredURL := range urlsToAuthenticate {
						handler.oidcRegistry.RegisterURL(discoveredURL, oidcCredential, "nuget resource")
					}
				}()
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
		handler.credentials = append(handler.credentials, feedCred)

		// If the credentials are for a specific feed, we query the base url to find all the resources
		// and authenticate them all
		if url != "" {
			logging.RequestLogf(nil, "fetching service index for nuget feed %s", url)
			// Same closure pattern as the OIDC block above — ensures the
			// HTTP response body is always closed via defer.
			func() {
				req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
				if err != nil {
					logging.RequestLogf(nil, "error creating http request (%s): %v", url, err)
					return
				}
				authenticateNugetRequest(req, feedCred, nil)

				rawRsp, err := httpClient.Do(req)
				if err != nil {
					logging.RequestLogf(nil, "error retrieving http response (%s): %v", url, err)
					return
				}
				defer rawRsp.Body.Close()

				body, err := io.ReadAll(rawRsp.Body)
				if err != nil {
					logging.RequestLogf(nil, "error reading http response body (%s): %v", url, err)
					return
				}

				switch rawRsp.StatusCode {
				case 401, 403:
					logging.RequestLogf(nil, "unauthorized for nuget feed %s", url)
					return
				}

				if rawRsp.StatusCode >= 400 {
					logging.RequestLogf(nil, "unexpected http response %d for nuget feed %s", rawRsp.StatusCode, url)
					return
				}

				urlsToAuthenticate := extraUrlsFromSourceResponse(body, url)
				for _, discoveredURL := range urlsToAuthenticate {
					feedCred := nugetFeedCredentials{
						url:      discoveredURL,
						token:    token,
						username: username,
						password: password,
					}
					handler.credentials = append(handler.credentials, feedCred)
					logging.RequestLogf(nil, "  added url to authentication list: %s", discoveredURL)
				}
			}()
		}
	}

	return &handler
}

func extraUrlsFromSourceResponse(body []byte, url string) []string {
	var urls []string
	bodyString := strings.TrimSpace(string(body))
	bodyReader := bytes.NewReader(body)
	switch {
	case strings.HasPrefix(bodyString, "<"):
		// XML v2 API
		urls = handleV2Response(bodyReader, url)
	case strings.HasPrefix(bodyString, "{"):
		// JSON v3 API
		urls = handleV3Response(bodyReader, url)
	default:
		logging.RequestLogf(nil, "unknown API response: %s...", bodyString[:10])
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

// HandleRequest adds auth to an nuget feed request
func (h *NugetFeedHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if (req.URL.Scheme != "http" && req.URL.Scheme != "https") || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	// Try OIDC credentials first (HTTPS only to avoid leaking tokens over plaintext)
	if req.URL.Scheme == "https" && h.oidcRegistry.TryAuth(req, ctx) {
		return req, nil
	}

	// Fall back to static credentials
	for _, cred := range h.credentials {
		if (cred.token == "" && cred.password == "") || (!helpers.UrlMatchesRequest(req, cred.url, true) && !helpers.CheckHost(req, cred.host)) {
			continue
		}

		authenticateNugetRequest(req, cred, ctx)

		return req, nil
	}

	return req, nil
}

func authenticateNugetRequest(req *http.Request, cred nugetFeedCredentials, ctx *goproxy.ProxyCtx) {
	token := cred.token
	if token == "" && cred.password != "" {
		token = cred.username + ":" + cred.password
	}
	username, password, found := strings.Cut(token, ":")
	if found {
		logging.RequestLogf(ctx, "* authenticating nuget feed request (host: %s, basic auth)", req.URL.Hostname())
		req.SetBasicAuth(username, password)
	} else if token != "" {
		if shouldTreatTokenAsPassword(req.URL) {
			logging.RequestLogf(ctx, "* authenticating nuget feed request (host: %s, basic auth for Azure DevOps)", req.URL.Hostname())
			req.SetBasicAuth("", token)
		} else {
			logging.RequestLogf(ctx, "* authenticating nuget feed request (host: %s, bearer auth)", req.URL.Hostname())
			req.Header.Set("authorization", "Bearer "+token)
		}
	}
}

func shouldTreatTokenAsPassword(url *url.URL) bool {
	if url.Hostname() == "pkgs.dev.azure.com" {
		return true
	}
	return strings.HasSuffix(url.Hostname(), ".pkgs.visualstudio.com") && strings.Contains(url.Path, "/_packaging/")
}
