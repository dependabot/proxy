package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestHexOrganizationHandler(t *testing.T) {
	dependabotToken := "123"
	deltaForceToken := "456"
	credentials := config.Credentials{
		config.Credential{
			"type":         "hex_organization",
			"organization": "dependabot",
			"token":        dependabotToken,
		},
		config.Credential{
			"type":         "hex_organization",
			"organization": "deltaforce",
			"token":        deltaForceToken,
		},
	}
	handler := NewHexOrganizationHandler(credentials)

	req := httptest.NewRequest("GET", "https://repo.hex.pm/repos/dependabot/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", dependabotToken, "dependabot registry request")

	req = httptest.NewRequest("GET", "https://repo.hex.pm/repos/deltaforce/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", deltaForceToken, "deltaforce registry request")

	// Not an org
	req = httptest.NewRequest("GET", "https://repo.hex.pm/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "not an org-scoped package")

	// Missing repo subdomain
	req = httptest.NewRequest("GET", "https://hex.pm/repos/deltaforce/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://repo.hex.pm/repos/deltaforce/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Not a GET request
	req = httptest.NewRequest("POST", "https://repo.hex.pm/repos/deltaforce/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "post request")
}
