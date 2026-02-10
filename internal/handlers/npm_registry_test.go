package handlers

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/dependabot/proxy/internal/config"
)

func TestNPMRegistryHandler(t *testing.T) {
	npmjsOrgToken := "1-2-3"
	privateRegToken := "4-5-6"
	nexusUser := "nexus"
	nexusPassword := "s0natyp3"
	credentials := config.Credentials{
		config.Credential{
			"type":     "npm_registry",
			"registry": "https://registry.npmjs.org",
			"token":    npmjsOrgToken,
		},
		config.Credential{
			"type":     "npm_registry",
			"registry": "example.com:443/reg-path",
			"token":    privateRegToken,
		},
		config.Credential{
			"type":     "npm_registry",
			"registry": "nexus.some-company.com",
			"token":    fmt.Sprintf("%s:%s", nexusUser, nexusPassword),
		},
		config.Credential{
			"type":     "npm_registry",
			"host":     "pkgs.dev.azure.com",
			"username": nexusUser,
			"password": nexusPassword,
		},
		config.Credential{
			"type":  "npm_registry",
			"url":   "https://example.org:443/reg-path",
			"token": privateRegToken,
		},
	}
	handler := NewNPMRegistryHandler(credentials)

	req := httptest.NewRequest("GET", "https://registry.npmjs.org/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", npmjsOrgToken, "valid registry request")

	req = httptest.NewRequest("GET", "https://registry.yarnpkg.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", npmjsOrgToken, "yarn registry request, given npmjs.org creds")

	req = httptest.NewRequest("GET", "https://example.com/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", privateRegToken, "valid registry request with port and path")

	req = httptest.NewRequest("GET", "https://example.org/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", privateRegToken, "valid registry request with port and path")

	req = httptest.NewRequest("GET", "https://example.com/other-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", privateRegToken, "different path")

	req = httptest.NewRequest("GET", "https://nexus.some-company.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, nexusUser, nexusPassword, "http basic auth")

	// Different subdomain
	req = httptest.NewRequest("GET", "https://foo.example.com/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://example.com/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Azure DevOps
	req = httptest.NewRequest("GET", "https://pkgs.dev.azure.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, nexusUser, nexusPassword, "azure devops registry request")

	// Azure DevOps case insensitive
	req = httptest.NewRequest("GET", "https://PKGS.dev.azure.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, nexusUser, nexusPassword, "azure devops case insensitive registry request")
}
