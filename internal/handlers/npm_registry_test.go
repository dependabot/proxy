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

	// Sibling path on the same host should NOT receive credentials from /reg-path
	req = httptest.NewRequest("GET", "https://example.com/other-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "sibling path should not match")

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

func TestNPMRegistryHandler_SameHostDifferentPaths(t *testing.T) {
	teamAToken := "team-a-token"
	teamBToken := "team-b-token"
	credentials := config.Credentials{
		config.Credential{
			"type":     "npm_registry",
			"registry": "https://artifactory.example.com/api/npm/team-a-npm",
			"token":    teamAToken,
		},
		config.Credential{
			"type":     "npm_registry",
			"registry": "https://artifactory.example.com/api/npm/team-b-npm",
			"token":    teamBToken,
		},
	}
	handler := NewNPMRegistryHandler(credentials)

	// Request to team-a path should use team-a token
	req := httptest.NewRequest("GET", "https://artifactory.example.com/api/npm/team-a-npm/@scope/pkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", teamAToken, "team-a path should use team-a token")

	// Request to team-b path should use team-b token, not team-a
	req = httptest.NewRequest("GET", "https://artifactory.example.com/api/npm/team-b-npm/@scope/pkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", teamBToken, "team-b path should use team-b token")

	// Request to unrelated path should not be authenticated
	req = httptest.NewRequest("GET", "https://artifactory.example.com/api/npm/team-c-npm/@scope/pkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "unrelated path should not match any credential")
}
