package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/config"
)

func TestOpenTofuRegistryHandler(t *testing.T) {
	var tests = []struct {
		credentials  config.Credentials
		registryType string
		host         string
		token        string
		url          string

		authorization string
	}{
		{
			credentials: config.Credentials{
				config.Credential{"type": "opentofu_registry", "host": "registry.example.org", "token": "header.body.signature"},
			},
			url:           "https://registry.example.org/v1/providers/org/name/versions",
			authorization: "Bearer header.body.signature",
		},
		{
			credentials: config.Credentials{
				config.Credential{"type": "opentofu_registry", "url": "https://registry.example.org", "token": "header.body.signature"},
			},
			url:           "https://registry.example.org/v1/providers/org/name/versions",
			authorization: "Bearer header.body.signature",
		},
		{
			credentials: config.Credentials{
				config.Credential{"type": "opentofu_registry", "host": "registry.example.org", "token": "header.body.signature"},
			},
			url:           "https://registry.opentofu.org/v1/providers/org/name/versions",
			authorization: "",
		},
		{
			credentials: config.Credentials{
				config.Credential{"type": "rubygems_server", "host": "registry.example.org", "token": "header.body.signature"},
			},
			url:           "https://registry.example.org/v1/providers/org/name/versions",
			authorization: "",
		},
		{
			credentials: config.Credentials{
				config.Credential{"type": "terraform_registry", "host": "registry.example.org", "token": "header.body.signature"},
			},
			url:           "https://registry.example.org/v1/providers/org/name/versions",
			authorization: "",
		},
		{
			credentials: config.Credentials{
				config.Credential{"type": "opentofu_registry", "host": "rEgIstRy.eXampLe.orG", "token": "token"},
			},
			url:           "https://registry.example.org/v1/providers/org/name/versions",
			authorization: "Bearer token",
		},
	}
	for _, tt := range tests {
		t.Run(strings.Join([]string{tt.registryType, tt.host, tt.token}, " "), func(t *testing.T) {
			handler := NewOpenTofuRegistryHandler(tt.credentials)

			request := handleRequestAndClose(handler, httptest.NewRequest("GET", tt.url, nil), nil)

			assert.Equal(t, tt.authorization, request.Header.Get("Authorization"))
		})
	}

	t.Run("HandleRequest without credentials", func(t *testing.T) {
		handler := NewOpenTofuRegistryHandler(config.Credentials{})

		url := "https://registry.opentofu.org/v1/providers/org/name/versions"
		request := handleRequestAndClose(handler, httptest.NewRequest("GET", url, nil), nil)

		assert.Equal(t, "", request.Header.Get("Authorization"), "should be empty")
	})

	t.Run("multiple credentials on same host with different URL paths", func(t *testing.T) {
		credentials := config.Credentials{
			config.Credential{"type": "opentofu_registry", "url": "https://registry.example.com/org1", "token": "token-org1"},
			config.Credential{"type": "opentofu_registry", "url": "https://registry.example.com/org2", "token": "token-org2"},
		}
		handler := NewOpenTofuRegistryHandler(credentials)

		// Request to org1 path should use org1 token
		req1 := handleRequestAndClose(handler, httptest.NewRequest("GET", "https://registry.example.com/org1/v1/providers/foo", nil), nil)
		assert.Equal(t, "Bearer token-org1", req1.Header.Get("Authorization"), "should use org1 token")

		// Request to org2 path should use org2 token
		req2 := handleRequestAndClose(handler, httptest.NewRequest("GET", "https://registry.example.com/org2/v1/providers/bar", nil), nil)
		assert.Equal(t, "Bearer token-org2", req2.Header.Get("Authorization"), "should use org2 token")

		// Request to unmatched path should not be authenticated
		req3 := handleRequestAndClose(handler, httptest.NewRequest("GET", "https://registry.example.com/org3/v1/providers/baz", nil), nil)
		assert.Equal(t, "", req3.Header.Get("Authorization"), "should not be authenticated")
	})

	t.Run("skips credentials with empty token", func(t *testing.T) {
		credentials := config.Credentials{
			config.Credential{"type": "opentofu_registry", "host": "registry.example.org", "token": ""},
		}
		handler := NewOpenTofuRegistryHandler(credentials)
		assert.Equal(t, 0, len(handler.credentials), "should skip credential with empty token")
	})

	t.Run("skips credentials with empty host and url", func(t *testing.T) {
		credentials := config.Credentials{
			config.Credential{"type": "opentofu_registry", "token": "some-token"},
		}
		handler := NewOpenTofuRegistryHandler(credentials)
		assert.Equal(t, 0, len(handler.credentials), "should skip credential with empty host and url")
	})

	t.Run("path boundary: /org should not match /org1", func(t *testing.T) {
		// Credentials are sorted longest-path-first to ensure /org1 matches before /org
		credentials := config.Credentials{
			config.Credential{"type": "opentofu_registry", "url": "https://registry.example.com/org", "token": "token-org"},
			config.Credential{"type": "opentofu_registry", "url": "https://registry.example.com/org1", "token": "token-org1"},
		}
		handler := NewOpenTofuRegistryHandler(credentials)

		assert.Equal(t, "https://registry.example.com/org1", handler.credentials[0].url, "longer path should be first")
		assert.Equal(t, "https://registry.example.com/org", handler.credentials[1].url, "shorter path should be second")

		req1 := handleRequestAndClose(handler, httptest.NewRequest("GET", "https://registry.example.com/org1/v1/providers/foo", nil), nil)
		assert.Equal(t, "Bearer token-org1", req1.Header.Get("Authorization"), "/org1 path should use org1 token")

		req2 := handleRequestAndClose(handler, httptest.NewRequest("GET", "https://registry.example.com/org/v1/providers/bar", nil), nil)
		assert.Equal(t, "Bearer token-org", req2.Header.Get("Authorization"), "/org path should use org token")

		// Request to /org123 should NOT match /org1 or /org (path boundary check)
		req3 := handleRequestAndClose(handler, httptest.NewRequest("GET", "https://registry.example.com/org123/v1/providers/baz", nil), nil)
		assert.Equal(t, "", req3.Header.Get("Authorization"), "/org123 should not match /org or /org1")
	})
}
