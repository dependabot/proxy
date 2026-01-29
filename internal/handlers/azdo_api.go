package handlers

import (
	"net/http"
	"strings"

	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"

	"github.com/dependabot/proxy/internal/config"
	"github.com/elazarl/goproxy"
)

// AzureDevOpsAPIHandler handles requests destined for the Azure DevOps API, adding auth
type AzureDevOpsAPIHandler struct {
	hostCredentials map[string][]azureDevOpsAPICredential
}

type azureDevOpsAPICredential struct {
	username string
	password string
}

var AzureDevOpsAPIHosts = []string{
	"dpdbot.dev.azure.com",
	"dpdbot.visualstudio.com",
	"dpdbot.codedev.ms",
	"dpdbot.vsts.me",
}

// NewAzureDevOpsAPIHandler returns a new AzureDevOpsAPIHandler, extracting the app
// access token from the array of credentials
func NewAzureDevOpsAPIHandler(creds config.Credentials) *AzureDevOpsAPIHandler {
	handler := AzureDevOpsAPIHandler{
		hostCredentials: map[string][]azureDevOpsAPICredential{},
	}

	for _, cred := range creds {
		if cred["type"] != "git_source" || !isAzureDevOpsAPIHost(cred.GetString("host")) {
			continue
		}

		host := strings.ToLower(cred.GetString("host"))
		credHost := host
		gitCred := azureDevOpsAPICredential{
			username: cred.GetString("username"),
			password: cred.GetString("password"),
		}

		hostCreds := handler.hostCredentials[credHost]
		handler.hostCredentials[credHost] = append(hostCreds, gitCred)
	}

	return &handler
}

// HandleRequest adds auth to an Azure DevOps API request
func (h *AzureDevOpsAPIHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if !h.isHandledAzureDevOpsAPIRequest(req) {
		return req, nil
	}

	if len(h.hostCredentials) == 0 {
		return req, nil
	}

	host := helpers.GetHost(req)
	creds := h.hostCredentials[host]
	if len(creds) == 0 {
		return req, nil
	}

	logging.RequestLogf(ctx, "* authenticating azure devops api request with token for %s", host)
	req.SetBasicAuth(creds[0].username, creds[0].password)

	// Azure DevOps requires an api-version to be set for requests. Add it if it is not present.
	var queryParams = req.URL.Query()
	if !queryParams.Has("api-version") {
		queryParams.Add("api-version", "7.2-preview")
		logging.RequestLogf(ctx, "* added default api-version to query parameters for azure devops api request")
	}

	req.URL.RawQuery = queryParams.Encode()

	return req, nil
}

func (h *AzureDevOpsAPIHandler) isHandledAzureDevOpsAPIRequest(req *http.Request) bool {
	return req.URL.Scheme == "https" && isAzureDevOpsAPIHost(helpers.GetHost(req))
}

func isAzureDevOpsAPIHost(host string) bool {
	for _, adoHost := range AzureDevOpsAPIHosts {
		if host == adoHost {
			return true
		}
	}
	return false
}
