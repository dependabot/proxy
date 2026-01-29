package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestCargoRegistryHandler(t *testing.T) {
	validURL := "https://valid-url.example.com"
	validNoProtocolURL := "valid-no-protocol-url.example.com"
	validURLWithPathBase := "https://valid-url-path.example.com"
	validURLWithPath := validURLWithPathBase + "/path"
	invalidURL := "asdf"
	noTokenURL := "https://no-token.example.com"

	token := "Bearer abc123"

	credentials := config.Credentials{
		config.Credential{
			"type":  "cargo_registry",
			"url":   validURL,
			"token": token,
		},
		config.Credential{
			"type":  "cargo_registry",
			"url":   validNoProtocolURL,
			"token": token,
		},
		config.Credential{
			"type":  "cargo_registry",
			"url":   validURLWithPath,
			"token": token,
		},
		config.Credential{
			"type":  "cargo_registry",
			"url":   invalidURL, // this should be ignored
			"token": token,
		},
		config.Credential{
			"type":  "cargo_registry",
			"url":   noTokenURL,
			"token": "",
		},
	}

	handler := NewCargoRegistryHandler(credentials)

	// valid request, should authenticate
	url := validURL
	req := httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "", token, "valid url request")

	// valid request plus a sub-path, should authenticate
	url = validURL + "/path"
	req = httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "", token, "valid url with sub-path request")

	// valid request for registry without protocol, should authenticate
	url = "https://" + validNoProtocolURL
	req = httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "", token, "valid url without protocol request")

	// valid request scoped to path, should authenticate
	url = validURLWithPath
	req = httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "", token, "valid path url request")

	// wrong path, shouldn't authenticate
	url = validURLWithPathBase + "/wrong_path"
	req = httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "requests to a mismatched path should not be authenticated")

	url = noTokenURL
	req = httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "should not authenticate when missing token")

	// HTTP, not HTTPS
	httpURL := strings.Replace(validURL, "https", "http", 1)
	url = httpURL
	req = httptest.NewRequest("GET", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "HTTP, not HTTPS request")

	// Non-GET request
	url = validURL
	req = httptest.NewRequest("POST", url, nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "non-GET request")
}
