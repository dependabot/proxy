package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestComposerHandler(t *testing.T) {
	bigCoUser := "taylorswift"
	bigCoPassword := "s3cr3t"
	smallCoToken := "t0k3n"
	smallCoUser := "ignored"
	smallCoPassword := "also-ignored"
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
	}
	handler := NewComposerHandler(credentials)

	req := httptest.NewRequest("GET", "https://phpreg.bigco.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, bigCoUser, bigCoPassword, "valid registry request")

	req = httptest.NewRequest("GET", "https://example.com/php/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, bigCoUser, bigCoPassword, "valid registry request")

	req = httptest.NewRequest("GET", "https://example.com/path/to/php/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, smallCoUser, smallCoPassword, "path-specific registry request")

	req = httptest.NewRequest("GET", "https://phpreg.smallco.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, smallCoToken, "", "valid registry request")

	// Missing repo subdomain
	req = httptest.NewRequest("GET", "https://bigco.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://phpreg.bigco.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Not a GET request
	req = httptest.NewRequest("POST", "https://phpreg.bigco.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "post request")
}
