package handlers

import (
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

	req := newTestRequest(t, "GET", "https://corp.dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, dependabotUser, dependabotPassword, "dependabot repository request")

	req = newTestRequest(t, "GET", "https://corp.deltaforce.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce repository request")

	// Path mismatch
	req = newTestRequest(t, "GET", "https://corp.dependabot.com/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "path mismatch")

	// Missing repo subdomain
	req = newTestRequest(t, "GET", "https://dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = newTestRequest(t, "GET", "http://corp.dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, dependabotUser, dependabotPassword, "dependabot repository http request")

	// HTTP, not HTTPS, missing submomain
	req = newTestRequest(t, "GET", "http://dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// Not a GET request
	req = newTestRequest(t, "POST", "https://corp.dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "post request")

	// No username and password in credential
	req = newTestRequest(t, "GET", "https://open.dependabot.com/maven2/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "no username and password")

	// Azure DevOps
	req = newTestRequest(t, "GET", "https://pkgs.dev.azure.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "azure devops repository request")

	// Azure DevOps case insensitive
	req = newTestRequest(t, "GET", "https://PKGS.dev.azure.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "azure devops case insensitive registry request")
}
