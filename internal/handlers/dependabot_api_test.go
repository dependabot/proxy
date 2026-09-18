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

	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://api.dependabot.com/update_jobs/123/create_pull_request", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", dependabotPassword, "dependabot repository request")

	// HTTP, not HTTPS
	req = httptest.NewRequestWithContext(t.Context(), "GET", "http://api.dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "we always use HTTPS")

	// missing subdomain
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")
}

func TestDependabotAPIHandler_CaseInsensitiveHostname(t *testing.T) {
	dependabotPassword := "Bearer 123"

	handler := NewDependabotAPIHandler(config.ProxyEnvSettings{
		APIEndpoint: "https://API.DEPENDABOT.COM",
		JobToken:    dependabotPassword,
	})

	// Request with lowercase hostname should still match uppercase endpoint
	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://api.dependabot.com/update_jobs/123/create_pull_request", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", dependabotPassword, "case-insensitive hostname matching")
}

func TestDependabotAPIHandler_SpoofedHost(t *testing.T) {
	handler := NewDependabotAPIHandler(config.ProxyEnvSettings{
		APIEndpoint: "https://api.dependabot.com",
		JobToken:    "test-job-token",
	})
	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://untrusted.example/update_jobs/123/details", nil)
	req.Host = "api.dependabot.com"

	req = handleRequestAndClose(handler, req, nil)

	assertUnauthenticated(t, req, "Host header must not override the destination")
}

func TestDependabotAPIHandler_Ports(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		destination string
		wantAuth    bool
	}{
		{name: "implicit default port", endpoint: "https://api.dependabot.com", destination: "https://api.dependabot.com", wantAuth: true},
		{name: "explicit request default port", endpoint: "https://api.dependabot.com", destination: "https://api.dependabot.com:443", wantAuth: true},
		{name: "explicit endpoint default port", endpoint: "https://api.dependabot.com:443", destination: "https://api.dependabot.com", wantAuth: true},
		{name: "matching custom port", endpoint: "https://api.dependabot.com:8443", destination: "https://api.dependabot.com:8443", wantAuth: true},
		{name: "different port", endpoint: "https://api.dependabot.com", destination: "https://api.dependabot.com:8443"},
		{name: "missing custom port", endpoint: "https://api.dependabot.com:8443", destination: "https://api.dependabot.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewDependabotAPIHandler(config.ProxyEnvSettings{
				APIEndpoint: tt.endpoint,
				JobToken:    "test-job-token",
			})
			req := httptest.NewRequestWithContext(t.Context(), "GET", tt.destination+"/update_jobs/123/details", nil)

			req = handleRequestAndClose(handler, req, nil)

			if tt.wantAuth {
				assertHasTokenAuth(t, req, "", "test-job-token", "matching API destination")
			} else {
				assertUnauthenticated(t, req, "different API port")
			}
		})
	}
}
