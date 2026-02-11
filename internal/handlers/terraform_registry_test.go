package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/config"
)

func TestTerraformRegistryHandler(t *testing.T) {
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
				config.Credential{"type": "terraform_registry", "host": "terraform.example.org", "token": "header.body.signature"},
			},
			url:           "https://terraform.example.org/v1/providers/org/name/versions",
			authorization: "Bearer header.body.signature",
		},
		{
			credentials: config.Credentials{
				config.Credential{"type": "terraform_registry", "url": "https://terraform.example.org", "token": "header.body.signature"},
			},
			url:           "https://terraform.example.org/v1/providers/org/name/versions",
			authorization: "Bearer header.body.signature",
		},
		{
			credentials: config.Credentials{
				config.Credential{"type": "terraform_registry", "host": "terraform.example.org", "token": "header.body.signature"},
			},
			url:           "https://registry.terraform.io/v1/providers/org/name/versions",
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
				config.Credential{"type": "terraform_registry", "host": "tErrAform.eXampLe.orG", "token": "token"},
			},
			url:           "https://terraform.example.org/v1/providers/org/name/versions",
			authorization: "Bearer token",
		},
	}
	for _, tt := range tests {
		t.Run(strings.Join([]string{tt.registryType, tt.host, tt.token}, " "), func(t *testing.T) {
			handler := NewTerraformRegistryHandler(tt.credentials)

			request := handleRequestAndClose(handler, httptest.NewRequest("GET", tt.url, nil), nil)

			assert.Equal(t, tt.authorization, request.Header.Get("Authorization"))
		})
	}

	t.Run("HandleRequest without credentials", func(t *testing.T) {
		handler := NewTerraformRegistryHandler(config.Credentials{})

		url := "https://registry.terraform.io/v1/providers/org/name/versions"
		request := handleRequestAndClose(handler, httptest.NewRequest("GET", url, nil), nil)

		assert.Equal(t, "", request.Header.Get("Authorization"), "should be empty")
	})
}
