package handlers

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/config"
)

func TestRubyGemsServerHandler(t *testing.T) {
	dependabotToken := "123"
	deltaForceUser := "some-user"
	deltaForcePassword := "456"
	pathUser := "gems-user"
	pathPassword := "789"

	credentials := config.Credentials{
		config.Credential{
			"type":  "rubygems_server",
			"host":  "corp.dependabot.com/gems/",
			"token": dependabotToken,
		},
		config.Credential{
			"type":  "rubygems_server",
			"host":  "corp.deltaforce.com:443/",
			"token": fmt.Sprintf("%s:%s", deltaForceUser, deltaForcePassword),
		},
		config.Credential{
			"type":  "rubygems_server",
			"url":   "https://example.com:443/gems",
			"token": fmt.Sprintf("%s:%s", deltaForceUser, deltaForcePassword),
		},
		config.Credential{
			"type":  "rubygems_server",
			"url":   "https://example.com:443/path/to/gems/",
			"token": fmt.Sprintf("%s:%s", pathUser, pathPassword),
		},
	}
	handler := NewRubyGemsServerHandler(credentials, testOIDCClient)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.dependabot.com/gems", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, dependabotToken, "", "dependabot registry request")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.deltaforce.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce registry request")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://example.com/gems/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce registry request")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://example.com/path/to/gems/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, pathUser, pathPassword, "path-specific registry request")

	// Path mismatch
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.dependabot.com/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "Path mismatch")

	// Missing repo subdomain
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://dependabot.com/gems", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequestWithContext(t.Context(), "GET", "http://corp.dependabot.com/gems", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Not a GET request
	req = httptest.NewRequestWithContext(t.Context(), "POST", "https://corp.dependabot.com/gems", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "post request")
}

func TestRubyGemsServerHandlerProxyOnlyCredentials(t *testing.T) {
	handler := NewRubyGemsServerHandler(config.Credentials{
		config.Credential{
			"type":       "rubygems_server",
			"host":       "rubygems.pkg.github.com",
			"token":      "x-access-token:automatic-token",
			"proxy-only": true,
		},
		config.Credential{
			"type":  "rubygems_server",
			"url":   "https://rubygems.pkg.github.com/dependabot",
			"token": "explicit-user:explicit-token",
		},
	}, testOIDCClient)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://rubygems.pkg.github.com/other/gem", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "x-access-token", "automatic-token", "host-only automatic credential")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://rubygems.pkg.github.com/other/gem", nil)
	req.Header.Set("Authorization", authorizationPlaceholder)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "x-access-token", "automatic-token", "automatic credential replaces placeholder auth")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://rubygems.pkg.github.com/other/gem", nil)
	req.Header.Set("Authorization", "Bearer request-token")
	req = handleRequestAndClose(handler, req, nil)
	assert.Equal(t, "Bearer request-token", req.Header.Get("Authorization"), "automatic credential preserves request auth")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://rubygems.pkg.github.com/dependabot/gem", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "explicit-user", "explicit-token", "path-specific explicit credential")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://rubygems.pkg.github.example/other/gem", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "automatic credential host mismatch")
}
