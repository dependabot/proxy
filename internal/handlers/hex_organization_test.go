package handlers

import (
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestHexOrganizationHandler(t *testing.T) {
	dependabotKey := "123"
	deltaForceKey := "456"
	credentials := config.Credentials{
		config.Credential{
			"type":         "hex_organization",
			"organization": "dependabot",
			"key":          dependabotKey,
		},
		config.Credential{
			"type":         "hex_organization",
			"organization": "deltaforce",
			"key":          deltaForceKey,
		},
	}
	handler := NewHexOrganizationHandler(credentials)

	req := newTestRequest(t, "GET", "https://repo.hex.pm/repos/dependabot/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", dependabotKey, "dependabot registry request")

	req = newTestRequest(t, "GET", "https://repo.hex.pm/repos/deltaforce/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", deltaForceKey, "deltaforce registry request")

	// Not an org
	req = newTestRequest(t, "GET", "https://repo.hex.pm/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "not an org-scoped package")

	// Missing repo subdomain
	req = newTestRequest(t, "GET", "https://hex.pm/repos/deltaforce/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = newTestRequest(t, "GET", "http://repo.hex.pm/repos/deltaforce/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Not a GET request
	req = newTestRequest(t, "POST", "https://repo.hex.pm/repos/deltaforce/packages/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "post request")
}

func TestHexOrganizationHandler_BackwardsCompatibility(t *testing.T) {
	t.Run("supports legacy token field", func(t *testing.T) {
		credentials := config.Credentials{
			config.Credential{
				"type":         "hex_organization",
				"organization": "legacy-org",
				"token":        "legacy-token",
			},
		}
		handler := NewHexOrganizationHandler(credentials)

		req := newTestRequest(t, "GET", "https://repo.hex.pm/repos/legacy-org/packages/foo", nil)
		req = handleRequestAndClose(handler, req, nil)
		assertHasTokenAuth(t, req, "", "legacy-token", "should support legacy token field")
	})

	t.Run("key takes precedence over token", func(t *testing.T) {
		credentials := config.Credentials{
			config.Credential{
				"type":         "hex_organization",
				"organization": "test-org",
				"key":          "new-key",
				"token":        "old-token",
			},
		}
		handler := NewHexOrganizationHandler(credentials)

		req := newTestRequest(t, "GET", "https://repo.hex.pm/repos/test-org/packages/foo", nil)
		req = handleRequestAndClose(handler, req, nil)
		assertHasTokenAuth(t, req, "", "new-key", "key should take precedence over token")
	})
}
