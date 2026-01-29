package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestGoProxyHandler(t *testing.T) {
	dependabotUser := "dbot"
	dependabotPassword := "123"
	deltaForceUser := "dforce"
	deltaForcePassword := "456"
	credentials := config.Credentials{
		config.Credential{
			"type":     "goproxy_server",
			"url":      "https://corp.dependabot.com/packages/",
			"username": dependabotUser,
			"password": dependabotPassword,
		},
		config.Credential{
			"type":     "goproxy_server",
			"url":      "https://corp.deltaforce.com:443/",
			"username": deltaForceUser,
			"password": deltaForcePassword,
		},
		config.Credential{
			"type": "goproxy_server",
			"url":  "https://open.dependabot.com/maven2/",
		},
		config.Credential{
			"type":     "goproxy_server",
			"host":     "pkgs.dev.azure.com",
			"username": deltaForceUser,
			"password": deltaForcePassword,
		},
	}
	handler := NewGoProxyServerHandler(credentials)

	req := httptest.NewRequest("GET", "https://corp.dependabot.com/packages/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, dependabotUser, dependabotPassword, "dependabot repository request")

	req = httptest.NewRequest("GET", "https://corp.deltaforce.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce repository request")

	// Path mismatch
	req = httptest.NewRequest("GET", "https://corp.dependabot.com/foo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "path mismatch")

	// Missing repo subdomain
	req = httptest.NewRequest("GET", "https://dependabot.com/packages/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://corp.dependabot.com/packages/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, dependabotUser, dependabotPassword, "dependabot repository http request")

	// HTTP, not HTTPS, missing submomain
	req = httptest.NewRequest("GET", "http://dependabot.com/packages/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// Not a GET request
	req = httptest.NewRequest("POST", "https://corp.dependabot.com/packages/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "post request")

	// No username and password in credential
	req = httptest.NewRequest("GET", "https://open.dependabot.com/maven2/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "no username and password")

	// Azure DevOps
	req = httptest.NewRequest("GET", "https://pkgs.dev.azure.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "azure devops repository request")

	// Azure DevOps case insensitive
	req = httptest.NewRequest("GET", "https://PKGS.dev.azure.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "azure devops case insensitive registry request")
}
