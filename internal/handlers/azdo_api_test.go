package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/config"
)

func TestAzureDevOpsAPIHandler(t *testing.T) {
	adoDependabotCred := testGitSourceCred("dpdbot.dev.azure.com", "x-access-token", "token123")
	adoVsDependabotCred := testGitSourceCred("dpdbot.visualstudio.com", "x-access-token", "token123")

	adoGitCred := testGitSourceCred("dev.azure.com", "x-access-token", "token123")

	credentials := config.Credentials{adoDependabotCred, adoVsDependabotCred, adoGitCred}
	handler := NewAzureDevOpsAPIHandler(credentials)

	// Valid ADO hostname API request
	req := httptest.NewRequest("GET", "https://dpdbot.dev.azure.com/", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, adoDependabotCred.GetString("username"), adoDependabotCred.GetString("password"), "valid api request")

	// Valid VS hostname API request
	req = httptest.NewRequest("GET", "https://dpdbot.visualstudio.com/", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, adoVsDependabotCred.GetString("username"), adoVsDependabotCred.GetString("password"), "valid api request")

	// Valid API request with port
	req = httptest.NewRequest("GET", "https://dpdbot.dev.azure.com:443/", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, adoDependabotCred.GetString("username"), adoDependabotCred.GetString("password"), "valid api request with port")

	// Different subdomain - not the AzureDevOps Dependabot API
	req = httptest.NewRequest("GET", "https://dev.azure.com/", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://dpdbot.dev.azure.com/", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "http, not https")
}

func TestAzureDevOpsAPIHandler_WorksAgainstDevFabric(t *testing.T) {
	adoDevFabricDependabotCred := testGitSourceCred("dpdbot.codedev.ms", "x-access-token", "token123")
	adoVsDevFabricDependabotCred := testGitSourceCred("dpdbot.vsts.me", "x-access-token", "token123")

	credentials := config.Credentials{adoDevFabricDependabotCred, adoVsDevFabricDependabotCred}
	handler := NewAzureDevOpsAPIHandler(credentials)

	// Valid DevFabric hostname API request
	req := httptest.NewRequest("GET", "https://dpdbot.codedev.ms/", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, adoDevFabricDependabotCred.GetString("username"), adoDevFabricDependabotCred.GetString("password"), "valid codedev.ms api request")

	// Valid VS DevFabric hostname API request
	req = httptest.NewRequest("GET", "https://dpdbot.vsts.me/", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, adoVsDevFabricDependabotCred.GetString("username"), adoVsDevFabricDependabotCred.GetString("password"), "valid vsts.me api request")
}

func TestAzureDevOpsAPIHandler_DoesNotHandleUnknownHostname(t *testing.T) {
	notAdoCreds := testGitSourceCred("not.azuredevops.ms", "x-access-token", "token123")

	credentials := config.Credentials{notAdoCreds}
	handler := NewAzureDevOpsAPIHandler(credentials)

	req := httptest.NewRequest("GET", "https://not.azuredevops.ms/", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "does not put credentials in unknown host")
}

func TestAzureDevOpsAPIHandler_AddsApiVersionIfMissing(t *testing.T) {
	adoDependabotCred := testGitSourceCred("dpdbot.dev.azure.com", "x-access-token", "token123")
	adoGitCred := testGitSourceCred("dev.azure.com", "x-access-token", "token123")

	credentials := config.Credentials{adoDependabotCred, adoGitCred}
	handler := NewAzureDevOpsAPIHandler(credentials)

	// Valid API request, adds a default api-version
	req := httptest.NewRequest("GET", "https://dpdbot.dev.azure.com/", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasQueryParam(t, req, "api-version", "7.2-preview", "adds a default api-version query param")

	// Valid API request, does not override existing query param
	req = httptest.NewRequest("GET", "https://dpdbot.dev.azure.com/?api-version=7.0", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasQueryParam(t, req, "api-version", "7.0", "adds a default api-version query param")

	// Valid API request, maintains existing query params when adding api-version
	req = httptest.NewRequest("GET", "https://dpdbot.dev.azure.com/?param1=test", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasQueryParam(t, req, "api-version", "7.2-preview", "adds a default api-version query param")
	assertHasQueryParam(t, req, "param1", "test", "maintains existing query params")
}

func assertHasQueryParam(t *testing.T, r *http.Request, key, value, msg string) {
	t.Run(msg, func(t *testing.T) {
		queryParams := r.URL.Query()
		assert.True(t, queryParams.Has(key), msg)
		assert.Equal(t, queryParams.Get(key), value, msg)
	})
}
