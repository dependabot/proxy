package handlers

import (
	"fmt"
	"net/http/httptest"
	"testing"

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
	handler := NewRubyGemsServerHandler(credentials)

	req := httptest.NewRequest("GET", "https://corp.dependabot.com/gems", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, dependabotToken, "", "dependabot registry request")

	req = httptest.NewRequest("GET", "https://corp.deltaforce.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce registry request")

	req = httptest.NewRequest("GET", "https://example.com/gems/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce registry request")

	req = httptest.NewRequest("GET", "https://example.com/path/to/gems/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, pathUser, pathPassword, "path-specific registry request")

	// Path mismatch
	req = httptest.NewRequest("GET", "https://corp.dependabot.com/foo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "Path mismatch")

	// Missing repo subdomain
	req = httptest.NewRequest("GET", "https://dependabot.com/gems", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://corp.dependabot.com/gems", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Not a GET request
	req = httptest.NewRequest("POST", "https://corp.dependabot.com/gems", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "post request")
}
