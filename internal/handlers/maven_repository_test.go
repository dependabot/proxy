package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestMavenRepositoryHandler(t *testing.T) {
	dependabotUser := "dbot"
	dependabotPassword := "123"
	deltaForceUser := "dforce"
	deltaForcePassword := "456"
	credentials := config.Credentials{
		config.Credential{
			"type":     "maven_repository",
			"url":      "https://corp.dependabot.com/packages/",
			"username": dependabotUser,
			"password": dependabotPassword,
		},
		config.Credential{
			"type":     "maven_repository",
			"url":      "https://corp.deltaforce.com:443/",
			"username": deltaForceUser,
			"password": deltaForcePassword,
		},
		config.Credential{
			"type": "maven_repository",
			"url":  "https://open.dependabot.com/maven2/",
		},
		config.Credential{
			"type":     "maven_repository",
			"host":     "pkgs.dev.azure.com",
			"username": deltaForceUser,
			"password": deltaForcePassword,
		},
	}
	handler := NewMavenRepositoryHandler(credentials, testOIDCClient)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, dependabotUser, dependabotPassword, "dependabot repository request")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.deltaforce.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce repository request")

	// Path mismatch
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.dependabot.com/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "path mismatch")

	// Missing repo subdomain
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequestWithContext(t.Context(), "GET", "http://corp.dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, dependabotUser, dependabotPassword, "dependabot repository http request")

	// HTTP, not HTTPS, missing submomain
	req = httptest.NewRequestWithContext(t.Context(), "GET", "http://dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// Not a GET request
	req = httptest.NewRequestWithContext(t.Context(), "POST", "https://corp.dependabot.com/packages/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "post request")

	// No username and password in credential
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://open.dependabot.com/maven2/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "no username and password")

	// Azure DevOps
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.dev.azure.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "azure devops repository request")

	// Azure DevOps case insensitive
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://PKGS.dev.azure.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "azure devops case insensitive registry request")
}
