package handlers

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
)

// DependabotAPIHandler injects the job token into requests to the Dependabot API
type DependabotAPIHandler struct {
	dependabotAPIHost string
	credentials       string
}

// NewDependabotAPIHandler constructs a new DependabotAPIHandler
func NewDependabotAPIHandler(envSettings config.ProxyEnvSettings) *DependabotAPIHandler {
	apiUrl, err := url.Parse(envSettings.APIEndpoint)
	if err != nil {
		log.Println("unable to parse API endpoint", err)
		return nil
	}

	handler := DependabotAPIHandler{
		dependabotAPIHost: strings.ToLower(apiUrl.Host),
		credentials:       envSettings.JobToken,
	}

	return &handler
}

// HandleRequest adds auth if the request is to the API endpoint
func (h *DependabotAPIHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" {
		return req, nil
	}

	if strings.ToLower(req.Host) != h.dependabotAPIHost {
		return req, nil
	}

	req.Header.Set("Authorization", h.credentials)

	return req, nil
}
