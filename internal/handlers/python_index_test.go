package handlers

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestPythonIndexHandler(t *testing.T) {
	dependabotToken := "123"
	dependabotSecToken := "dependabot:sec123"
	simpleSecToken := "simple:sec245"
	deltaForceUser := "some-user"
	deltaForcePassword := "456"
	credentials := config.Credentials{
		config.Credential{
			"type":      "python_index",
			"index-url": "https://corp.dependabot.com/pyreg/",
			"token":     dependabotToken,
		},
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pypy.com/dependabot/+simple/",
			"token":     dependabotSecToken,
		},
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pypy.com/simple/simple/",
			"token":     simpleSecToken,
		},
		config.Credential{
			"type":      "python_index",
			"index-url": "https://corp.deltaforce.com:443/",
			"token":     fmt.Sprintf("%s:%s", deltaForceUser, deltaForcePassword),
		},
		config.Credential{
			"type":     "python_index",
			"host":     "pkgs.dev.azure.com",
			"username": deltaForceUser,
			"password": deltaForcePassword,
		},
		config.Credential{
			"type":  "python_index",
			"url":   "https://example.com:443/",
			"token": fmt.Sprintf("%s:%s", deltaForceUser, deltaForcePassword),
		},
	}
	handler := NewPythonIndexHandler(credentials)

	req := httptest.NewRequest("GET", "https://corp.dependabot.com/pyreg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, dependabotToken, "", "dependabot registry request")

	req = httptest.NewRequest("GET", "https://corp.deltaforce.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce registry request")

	req = httptest.NewRequest("GET", "https://example.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce registry request")

	// Path mismatch
	req = httptest.NewRequest("GET", "https://corp.dependabot.com/foo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "dependabot registry request")

	req = httptest.NewRequest("GET", "https://pypy.com/other/pgk/a", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "other registry request")

	// Path mismatch on /+simple
	req = httptest.NewRequest("GET", "https://pypy.com/dependabot/pgk/a", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, "dependabot", "sec123", "dependabot pypy registry request")

	// Path mismatch on /simple
	req = httptest.NewRequest("GET", "https://pypy.com/simple/pgk/a", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, "simple", "sec245", "simple pypy registry request")

	// Missing repo subdomain
	req = httptest.NewRequest("GET", "https://dependabot.com/pyreg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://corp.dependabot.com/pyreg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Not a GET request
	req = httptest.NewRequest("POST", "https://corp.dependabot.com/pyreg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "post request")

	// Azure DevOps
	req = httptest.NewRequest("GET", "https://pkgs.dev.azure.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "azure devops registry request")

	// Azure DevOps case insensitive
	req = httptest.NewRequest("GET", "https://PKGS.dev.azure.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "azure devops case insensitive registry request")
}
