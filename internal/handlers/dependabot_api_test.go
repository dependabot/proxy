package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestDependabotAPIHandler_HandleRequest(t *testing.T) {
	dependabotPassword := "Bearer 123"

	handler := NewDependabotAPIHandler(config.ProxyEnvSettings{
		APIEndpoint: "https://api.dependabot.com",
		JobToken:    dependabotPassword,
	})

	req := httptest.NewRequest("GET", "https://api.dependabot.com/update_jobs/123/create_pull_request", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "", dependabotPassword, "dependabot repository request")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://api.dependabot.com/packages/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "we always use HTTPS")

	// missing subdomain
	req = httptest.NewRequest("GET", "https://dependabot.com/packages/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "different subdomain")
}

func TestDependabotAPIHandler_CaseInsensitiveHostname(t *testing.T) {
	dependabotPassword := "Bearer 123"

	handler := NewDependabotAPIHandler(config.ProxyEnvSettings{
		APIEndpoint: "https://API.DEPENDABOT.COM",
		JobToken:    dependabotPassword,
	})

	// Request with lowercase hostname should still match uppercase endpoint
	req := httptest.NewRequest("GET", "https://api.dependabot.com/update_jobs/123/create_pull_request", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "", dependabotPassword, "case-insensitive hostname matching")
}
