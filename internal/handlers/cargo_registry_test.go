package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dependabot/proxy/internal/config"
	"github.com/elazarl/goproxy"
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

func TestCargoRegistryHandlerConfigJsonResponse(t *testing.T) {
	validURL := "https://valid-url.example.com"
	token := "Bearer abc123" //nolint:gosec // test credential

	credentials := config.Credentials{
		config.Credential{
			"type":  "cargo_registry",
			"url":   validURL,
			"token": token,
		},
	}

	handler := NewCargoRegistryHandler(credentials)

	tests := []struct {
		name          string
		requestPath   string
		responseBody  interface{}
		expectRewrite bool
		checkModified func(t *testing.T, body []byte)
	}{
		{
			name:          "config.json with auth-required should be removed",
			requestPath:   "/index/te/st/config.json",
			responseBody:  map[string]interface{}{"auth-required": true, "dl": "https://example.com/download"},
			expectRewrite: true,
			checkModified: func(t *testing.T, body []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if _, exists := result["auth-required"]; exists {
					t.Error("auth-required property should have been removed")
				}
				if dl, ok := result["dl"].(string); !ok || dl != "https://example.com/download" {
					t.Error("dl property should be preserved")
				}
			},
		},
		{
			name:          "config.json without auth-required should not be modified",
			requestPath:   "/index/te/st/config.json",
			responseBody:  map[string]interface{}{"dl": "https://example.com/download"},
			expectRewrite: false,
			checkModified: func(t *testing.T, body []byte) {},
		},
		{
			name:          "non-config.json paths should not be rewritten",
			requestPath:   "/index/te/st/package.json",
			responseBody:  map[string]interface{}{"auth-required": true},
			expectRewrite: false,
			checkModified: func(t *testing.T, body []byte) {},
		},
		{
			name:          "invalid JSON should not be rewritten",
			requestPath:   "/index/te/st/config.json",
			responseBody:  "not valid json",
			expectRewrite: false,
			checkModified: func(t *testing.T, body []byte) {
				if string(body) != "not valid json" {
					t.Error("invalid JSON response should be unchanged")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create response body
			var respBody []byte
			if str, ok := tt.responseBody.(string); ok {
				respBody = []byte(str)
			} else {
				var err error
				respBody, err = json.Marshal(tt.responseBody)
				if err != nil {
					t.Fatalf("failed to marshal response body: %v", err)
				}
			}

			// Create request and response
			req := httptest.NewRequest("GET", validURL+tt.requestPath, nil)
			rsp := &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(respBody)),
				Header:     make(http.Header),
			}

			// Create proxy context
			proxyCtx := &goproxy.ProxyCtx{
				Req: req,
			}

			// Call HandleResponse
			modifiedRsp := handler.HandleResponse(rsp, proxyCtx)

			// Read modified response body
			modifiedBody, err := io.ReadAll(modifiedRsp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			// Check if it was rewritten
			if tt.expectRewrite {
				if len(modifiedBody) >= len(respBody) && string(modifiedBody) == string(respBody) {
					t.Error("response should have been rewritten")
				}
			} else {
				if string(modifiedBody) != string(respBody) {
					t.Errorf("response should not have been modified, got %s, expected %s", string(modifiedBody), string(respBody))
				}
			}

			// Run custom check
			tt.checkModified(t, modifiedBody)
		})
	}
}
