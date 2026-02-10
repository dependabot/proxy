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
	credentials     []nugetFeedCredentials
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
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
		credentials:     []nugetFeedCredentials{},
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
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

		oidcCredential, _ := oidc.CreateOIDCCredential(cred)
		if oidcCredential != nil {
			key := url
			if key == "" {
				key = host
			}

			if key != "" {
				handler.oidcCredentials[key] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for nuget feed: %s", oidcCredential.Provider(), key)

				// now query all resources to add to the authentication list
				req, err := http.NewRequest("GET", key, nil)
				if err != nil {
					logging.RequestLogf(nil, "error creating http request (%s): %v", key, err)
					continue
				}

				if oidc.TryAuthOIDCRequestWithPrefix(&handler.mutex, handler.oidcCredentials, req, nil) {
					rawRsp, err := httpClient.Do(req)
					if err != nil {
						logging.RequestLogf(nil, "error retrieving http response (%s): %v", key, err)
						continue
					}

					body, err := io.ReadAll(rawRsp.Body)
					if err != nil {
						logging.RequestLogf(nil, "error reading http response body")
						continue
					}
					rawRsp.Body.Close()

					switch rawRsp.StatusCode {
					case 401, 403:
						logging.RequestLogf(nil, "unauthorized for nuget feed %s", key)
						continue
					}

					if rawRsp.StatusCode >= 400 {
						logging.RequestLogf(nil, "unexpected http response %d for nuget feed %s", rawRsp.StatusCode, key)
						continue
					}

					urlsToAuthenticate := extraUrlsFromSourceResponse(body, key)
					for _, url := range urlsToAuthenticate {
						handler.oidcCredentials[url] = oidcCredential
						logging.RequestLogf(nil, "  registered %s OIDC credentials for nuget resource: %s", oidcCredential.Provider(), url)
					}
				}
			}
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
			req, err := http.NewRequest("GET", url, nil)
			authenticateNugetRequest(req, feedCred, nil)
			if err != nil {
				logging.RequestLogf(nil, "error creating http request (%s): %v", url, err)
				continue
			}

			rawRsp, err := httpClient.Do(req)
			if err != nil {
				logging.RequestLogf(nil, "error retrieving http response (%s): %v", url, err)
				continue
			}

			body, err := io.ReadAll(rawRsp.Body)
			if err != nil {
				logging.RequestLogf(nil, "error reading http response body")
				continue
			}
			rawRsp.Body.Close()

			switch rawRsp.StatusCode {
			case 401, 403:
				logging.RequestLogf(nil, "unauthorized for nuget feed %s", url)
				continue
			}

			if rawRsp.StatusCode >= 400 {
				logging.RequestLogf(nil, "unexpected http response %d for nuget feed %s", rawRsp.StatusCode, url)
				continue
			}

			urlsToAuthenticate := extraUrlsFromSourceResponse(body, url)
			for _, url := range urlsToAuthenticate {
				feedCred := nugetFeedCredentials{
					url:      url,
					token:    token,
					username: username,
					password: password,
				}
				handler.credentials = append(handler.credentials, feedCred)
				logging.RequestLogf(nil, "  added url to authentication list: %s", url)
			}
		}
	}

	return &handler
}

func extraUrlsFromSourceResponse(body []byte, url string) []string {
	var urls []string
	bodyString := strings.TrimSpace(string(body))
	bodyReader := bytes.NewReader(body)
	if strings.HasPrefix(bodyString, "<") {
		// XML v2 API
		urls = handleV2Response(bodyReader, url)
	} else if strings.HasPrefix(bodyString, "{") {
		// JSON v3 API
		urls = handleV3Response(bodyReader, url)
	} else {
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

	// Try OIDC credentials first
	if oidc.TryAuthOIDCRequestWithPrefix(&h.mutex, h.oidcCredentials, req, ctx) {
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
