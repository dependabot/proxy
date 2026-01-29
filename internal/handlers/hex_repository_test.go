package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestHexRepositoryHandler(t *testing.T) {
	validConfigUrl := "https://valid-config.example.com"
	noAuthKeyUrl := "https://no-auth-key.example.com"

	authKey := "abc123"

	credentials := config.Credentials{
		config.Credential{
			"type":     "hex_repository",
			"url":      validConfigUrl,
			"auth-key": authKey,
		},
		config.Credential{
			"type":     "hex_repository",
			"url":      noAuthKeyUrl,
			"auth-key": "",
		},
	}

	validPath := "/repos/my_wonderful_repo/version"

	handler := NewHexRepositoryHandler(credentials)

	// valid request, should authenticate
	url := validConfigUrl + validPath
	req := httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "", authKey, "dependabot registry request")

	// requests to /public_key are passed through
	url = validConfigUrl + "/public_key"
	req = httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "requests to /public_key should not be authenticated")

	url = noAuthKeyUrl + validPath
	req = httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "should not authenticate when missing auth key")

	// path isn't defined correctly
	url = validConfigUrl + "/packages/jason"
	req = httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "", authKey, "alternative registry request")

	// HTTP, not HTTPS
	httpUrl := strings.Replace(validConfigUrl, "https", "http", 1)
	url = httpUrl + validPath
	req = httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "HTTP, not HTTPS request")

	// Non-GET request
	url = validConfigUrl + validPath
	req = httptest.NewRequest("POST", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "non-GET request")
}
