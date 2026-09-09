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
	"sync"

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
	url       string
	host      string
	token     string
	username  string
	password  string
	proxyOnly bool
}

const nugetDiscoveryConcurrency = 8

type nugetDiscoveryJob struct {
	serviceIndexURL     string
	staticCredential    nugetFeedCredentials
	staticCredentialSet int
	oidcCredential      *oidc.OIDCCredential
}

// NewNugetFeedHandler returns a new NugetFeedHandler.
func NewNugetFeedHandler(creds config.Credentials, client *http.Client) *NugetFeedHandler {
	handler := NugetFeedHandler{
		credentials:  []nugetFeedCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(client),
	}
	staticCredentialSets := make([][]nugetFeedCredentials, 0)
	discoveryJobs := make([]nugetDiscoveryJob, 0)

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

		proxyOnly := cred.GetBool("proxy-only")
		if proxyOnly {
			if host == "" {
				continue
			}
			url = ""
		} else {
			oidcCredential, _, ok := handler.oidcRegistry.Register(cred, []string{"url"}, "nuget feed")
			if ok {
				if url != "" {
					discoveryJobs = append(discoveryJobs, nugetDiscoveryJob{
						serviceIndexURL:     url,
						staticCredentialSet: -1,
						oidcCredential:      oidcCredential,
					})
				}
				continue
			}
			// OIDC credentials are not used as static credentials.
			if oidcCredential != nil {
				continue
			}
		}

		feedCred := nugetFeedCredentials{
			url:       url,
			host:      host,
			token:     token,
			username:  username,
			password:  password,
			proxyOnly: proxyOnly,
		}
		staticCredentialSet := len(staticCredentialSets)
		staticCredentialSets = append(staticCredentialSets, []nugetFeedCredentials{feedCred})

		// If the credentials are for a specific feed, we query the base url to find all the resources
		// and authenticate them all
		if !proxyOnly && url != "" {
			logging.RequestLogf(nil, "fetching service index for nuget feed %s", url)
			discoveryJobs = append(discoveryJobs, nugetDiscoveryJob{
				serviceIndexURL:     url,
				staticCredential:    feedCred,
				staticCredentialSet: staticCredentialSet,
			})
		}
	}

	discoveredURLs := discoverNugetFeedURLs(discoveryJobs, client, handler.oidcRegistry)
	for i, job := range discoveryJobs {
		if job.oidcCredential != nil {
			for _, discoveredURL := range discoveredURLs[i] {
				handler.oidcRegistry.RegisterURL(discoveredURL, job.oidcCredential, "nuget resource")
			}
			continue
		}

		for _, discoveredURL := range discoveredURLs[i] {
			staticCredentialSets[job.staticCredentialSet] = append(
				staticCredentialSets[job.staticCredentialSet],
				nugetFeedCredentials{
					url:      discoveredURL,
					token:    job.staticCredential.token,
					username: job.staticCredential.username,
					password: job.staticCredential.password,
				},
			)
			logging.RequestLogf(nil, "  added url to authentication list: %s", discoveredURL)
		}
	}
	for _, credentialSet := range staticCredentialSets {
		handler.credentials = append(handler.credentials, credentialSet...)
	}

	return &handler
}

func discoverNugetFeedURLs(
	jobs []nugetDiscoveryJob,
	client *http.Client,
	oidcRegistry *oidc.OIDCRegistry,
) [][]string {
	results := make([][]string, len(jobs))
	if len(jobs) == 0 {
		return results
	}

	jobIndexes := make(chan int)
	workerCount := min(nugetDiscoveryConcurrency, len(jobs))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for jobIndex := range jobIndexes {
				results[jobIndex] = discoverNugetFeedURLsForJob(jobs[jobIndex], client, oidcRegistry)
			}
		}()
	}
	for jobIndex := range jobs {
		jobIndexes <- jobIndex
	}
	close(jobIndexes)
	workers.Wait()

	return results
}

func discoverNugetFeedURLsForJob(
	job nugetDiscoveryJob,
	client *http.Client,
	oidcRegistry *oidc.OIDCRegistry,
) []string {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, job.serviceIndexURL, nil)
	if err != nil {
		logging.RequestLogf(nil, "error creating http request (%s): %v", job.serviceIndexURL, err)
		return nil
	}

	if job.oidcCredential != nil {
		if req.URL.Scheme != "https" {
			logging.RequestLogf(nil, "refusing to discover nuget feed over non-https URL %s", job.serviceIndexURL)
			return nil
		}
		if !oidcRegistry.TryAuthCredential(req, nil, job.oidcCredential) {
			return nil
		}
	} else {
		authenticateNugetRequest(req, job.staticCredential, nil)
	}

	rawRsp, err := client.Do(req)
	if err != nil {
		logging.RequestLogf(nil, "error retrieving http response (%s): %v", job.serviceIndexURL, err)
		return nil
	}
	defer rawRsp.Body.Close()

	body, err := io.ReadAll(rawRsp.Body)
	if err != nil {
		logging.RequestLogf(nil, "error reading http response body (%s): %v", job.serviceIndexURL, err)
		return nil
	}

	switch rawRsp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		logging.RequestLogf(nil, "unauthorized for nuget feed %s", job.serviceIndexURL)
		return nil
	}
	if rawRsp.StatusCode != http.StatusOK {
		logging.RequestLogf(nil, "unexpected http response %d for nuget feed %s", rawRsp.StatusCode, job.serviceIndexURL)
		return nil
	}

	return extraUrlsFromSourceResponse(body, job.serviceIndexURL)
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

// HandleRequest adds auth to an nuget feed request
func (h *NugetFeedHandler) HandleRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
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

	if credential := h.staticCredentialForRequest(req, false); credential != nil {
		authenticateNugetRequest(req, *credential, proxyCtx)
		return req, nil
	}
	if hasUsableAuthorization(req) || oidcCredential != nil || !proxyOnlyCredentialRequestAllowed(req) {
		return req, nil
	}
	if credential := h.staticCredentialForRequest(req, true); credential != nil {
		authenticateNugetRequest(req, *credential, proxyCtx)
	}

	return req, nil
}

func (h *NugetFeedHandler) staticCredentialForRequest(req *http.Request, proxyOnly bool) *nugetFeedCredentials {
	var urlCredential *nugetFeedCredentials
	var hostCredential *nugetFeedCredentials
	bestSpecificity := -1
	for i := range h.credentials {
		cred := &h.credentials[i]
		if cred.proxyOnly != proxyOnly || (cred.token == "" && cred.password == "") {
			continue
		}
		if !proxyOnly && helpers.CredentialURLMatchesRequest(req, cred.url, true) {
			parsedURL, err := helpers.ParseURLLax(cred.url)
			if err == nil {
				path, ok := helpers.CanonicalPath(parsedURL.EscapedPath())
				specificity := strings.Count(path, "/")
				if ok && specificity > bestSpecificity {
					urlCredential = cred
					bestSpecificity = specificity
				}
			}
		}
		if hostCredential == nil && helpers.CheckHost(req, cred.host) {
			hostCredential = cred
		}
	}

	if urlCredential != nil {
		credential := *urlCredential
		return &credential
	}
	if hostCredential != nil {
		credential := *hostCredential
		return &credential
	}
	return nil
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
