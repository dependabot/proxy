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
	noTokenURL := "https://no-token.example.com" //nolint:gosec // test URL, not a credential

	token := "Bearer abc123" //nolint:gosec // test credential

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
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", token, "valid url request")

	// valid request plus a sub-path, should authenticate
	url = validURL + "/path"
	req = httptest.NewRequest("GET", url, nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", token, "valid url with sub-path request")

	// valid request for registry without protocol, should authenticate
	url = "https://" + validNoProtocolURL
	req = httptest.NewRequest("GET", url, nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", token, "valid url without protocol request")

	// valid request scoped to path, should authenticate
	url = validURLWithPath
	req = httptest.NewRequest("GET", url, nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", token, "valid path url request")

	// wrong path, shouldn't authenticate
	url = validURLWithPathBase + "/wrong_path"
	req = httptest.NewRequest("GET", url, nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "requests to a mismatched path should not be authenticated")

	url = noTokenURL
	req = httptest.NewRequest("GET", url, nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "should not authenticate when missing token")

	// HTTP, not HTTPS
	httpURL := strings.Replace(validURL, "https", "http", 1)
	url = httpURL
	req = httptest.NewRequest("GET", url, nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "HTTP, not HTTPS request")

	// Non-GET request
	url = validURL
	req = httptest.NewRequest("POST", url, nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "non-GET request")
}

func TestCargoRegistryHandlerWithHost(t *testing.T) {
	token := "Bearer abc123" //nolint:gosec // test credential

	credentials := config.Credentials{
		config.Credential{
			"type":  "cargo_registry",
			"host":  "cargo.example.com",
			"token": token,
		},
	}

	handler := NewCargoRegistryHandler(credentials)

	// matching host should authenticate
	req := httptest.NewRequest("GET", "https://cargo.example.com/some/path", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", token, "host-matched request")

	// non-matching host should not authenticate
	req = httptest.NewRequest("GET", "https://other.example.com/some/path", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "non-matching host request")

	// HTTP should not authenticate
	req = httptest.NewRequest("GET", "http://cargo.example.com/some/path", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "HTTP request to matching host")
}

func TestCargoRegistryHandlerWithUsernamePassword(t *testing.T) {
	username := "some-user"
	password := "some-password"

	credentials := config.Credentials{
		config.Credential{
			"type":     "cargo_registry",
			"url":      "https://cargo.example.com/registry",
			"username": username,
			"password": password,
		},
	}

	handler := NewCargoRegistryHandler(credentials)

	// matching url should authenticate with basic auth
	req := httptest.NewRequest("GET", "https://cargo.example.com/registry/crate", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, username, password, "basic auth via username/password")

	// non-matching url should not authenticate
	req = httptest.NewRequest("GET", "https://other.example.com/registry/crate", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "non-matching url should not authenticate")
}

func TestCargoRegistryHandlerWithHostAndUsernamePassword(t *testing.T) {
	username := "some-user"
	password := "some-password"

	credentials := config.Credentials{
		config.Credential{
			"type":     "cargo_registry",
			"host":     "cargo.example.com",
			"username": username,
			"password": password,
		},
	}

	handler := NewCargoRegistryHandler(credentials)

	// matching host should authenticate with basic auth
	req := httptest.NewRequest("GET", "https://cargo.example.com/any/path", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, username, password, "host-matched basic auth")

	// non-matching host should not authenticate
	req = httptest.NewRequest("GET", "https://other.example.com/any/path", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "non-matching host should not authenticate")
}

func TestCargoRegistryHandlerTokenTakesPrecedenceOverPassword(t *testing.T) {
	token := "Bearer abc123" //nolint:gosec // test credential

	credentials := config.Credentials{
		config.Credential{
			"type":     "cargo_registry",
			"url":      "https://cargo.example.com/registry",
			"token":    token,
			"username": "user",
			"password": "pass",
		},
	}

	handler := NewCargoRegistryHandler(credentials)

	// token should take precedence over username/password
	req := httptest.NewRequest("GET", "https://cargo.example.com/registry/crate", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "", token, "token takes precedence over password")
}

func TestCargoRegistryHandlerIgnoresNoUrlOrHost(t *testing.T) {
	credentials := config.Credentials{
		config.Credential{
			"type":  "cargo_registry",
			"token": "some-token",
		},
	}

	handler := NewCargoRegistryHandler(credentials)

	// should not authenticate any request since no url or host was provided
	req := httptest.NewRequest("GET", "https://anything.example.com/path", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "credential with no url or host should be ignored")
}
