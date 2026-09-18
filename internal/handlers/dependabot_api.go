package handlers

import (
	"log"
	"net/http"
	"net/url"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/elazarl/goproxy"
)

// DependabotAPIHandler injects the job token into requests to the Dependabot API
type DependabotAPIHandler struct {
	dependabotAPIURL string
	credentials      string
}

// NewDependabotAPIHandler constructs a new DependabotAPIHandler
func NewDependabotAPIHandler(envSettings config.ProxyEnvSettings) *DependabotAPIHandler {
	apiUrl, err := url.Parse(envSettings.APIEndpoint)
	if err != nil {
		log.Println("unable to parse API endpoint", err)
		return nil
	}

	handler := DependabotAPIHandler{
		dependabotAPIURL: apiUrl.String(),
		credentials:      envSettings.JobToken,
	}

	return &handler
}

// HandleRequest adds auth if the request is to the API endpoint
func (h *DependabotAPIHandler) HandleRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" {
		return req, nil
	}

	if !helpers.UrlMatchesRequest(req, h.dependabotAPIURL, false) {
		return req, nil
	}

	req.Header.Set("Authorization", h.credentials)

	return req, nil
}
