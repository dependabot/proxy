package handlers

import (
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestComposerHandler(t *testing.T) {
	bigCoUser := "taylorswift"
	bigCoPassword := "s3cr3t"
	smallCoToken := "t0k3n"
	smallCoUser := "ignored"
	smallCoPassword := "also-ignored"
	bearerToken := "bearer-secret-token"
	credentials := config.Credentials{
		config.Credential{
			"type":     "composer_repository",
			"registry": "phpreg.bigco.com",
			"username": bigCoUser,
			"password": bigCoPassword,
		},
		config.Credential{
			"type":     "composer_repository",
			"registry": "phpreg.smallco.com",
			"username": smallCoToken,
			"password": "",
		},
		config.Credential{
			"type":     "composer_repository",
			"url":      "https://example.com/php",
			"username": bigCoUser,
			"password": bigCoPassword,
		},
		config.Credential{
			"type":     "composer_repository",
			"url":      "https://example.com/path/to/php",
			"username": smallCoUser,
			"password": smallCoPassword,
		},
		config.Credential{
			"type":     "composer_repository",
			"registry": "phpreg.tokenco.com",
			"token":    bearerToken,
		},
		config.Credential{
			"type":  "composer_repository",
			"url":   "https://packages.tokenco.com/php",
			"token": bearerToken,
		},
		config.Credential{
			"type":     "composer_repository",
			"registry": "phpreg.precedence.com",
			"username": smallCoUser,
			"password": smallCoPassword,
			"token":    bearerToken,
		},
		config.Credential{
			"type":     "composer_repository",
			"registry": "phpreg.emptytoken.com",
			"username": smallCoUser,
			"password": smallCoPassword,
			"token":    "",
		},
	}
	handler := NewComposerHandler(credentials)

	req := newTestRequest(t, "GET", "https://phpreg.bigco.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, bigCoUser, bigCoPassword, "valid registry request")

	req = newTestRequest(t, "GET", "https://example.com/php/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, bigCoUser, bigCoPassword, "valid registry request")

	req = newTestRequest(t, "GET", "https://example.com/path/to/php/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, smallCoUser, smallCoPassword, "path-specific registry request")

	req = newTestRequest(t, "GET", "https://phpreg.smallco.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, smallCoToken, "", "valid registry request")

	req = newTestRequest(t, "GET", "https://phpreg.tokenco.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", bearerToken, "valid registry request with token")

	req = newTestRequest(t, "GET", "https://packages.tokenco.com/php/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", bearerToken, "valid path request with token")

	req = newTestRequest(t, "GET", "https://packages.tokenco.com/other/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "path token request outside configured path")

	req = newTestRequest(t, "GET", "https://phpreg.precedence.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", bearerToken, "token takes precedence over basic auth")

	req = newTestRequest(t, "GET", "https://phpreg.emptytoken.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, smallCoUser, smallCoPassword, "empty token falls back to basic auth")

	// Missing repo subdomain
	req = newTestRequest(t, "GET", "https://bigco.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = newTestRequest(t, "GET", "http://phpreg.bigco.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Not a GET request
	req = newTestRequest(t, "POST", "https://phpreg.bigco.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "post request")
}
