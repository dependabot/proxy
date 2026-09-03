package handlers

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

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
			"registry": "https://Registry.Npmjs.Org",
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
	handler := NewNPMRegistryHandler(credentials, testOIDCClient)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://registry.npmjs.org/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", npmjsOrgToken, "valid registry request")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://registry.yarnpkg.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", npmjsOrgToken, "yarn registry request, given npmjs.org creds")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://example.com/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", privateRegToken, "valid registry request with port and path")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://example.org/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", privateRegToken, "valid registry request with port and path")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://example.org/reg-path-attacker/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "URL-only registry sibling path")

	// Sibling path on the same host should NOT receive credentials from /reg-path
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://example.com/other-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "sibling path should not match")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://nexus.some-company.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, nexusUser, nexusPassword, "http basic auth")

	// Different subdomain
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://foo.example.com/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequestWithContext(t.Context(), "GET", "http://example.com/reg-path/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Azure DevOps
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.dev.azure.com/private-package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, nexusUser, nexusPassword, "azure devops registry request")

	// Azure DevOps case insensitive
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://PKGS.dev.azure.com/private-package", nil)
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
	handler := NewNPMRegistryHandler(credentials, testOIDCClient)

	// Request to team-a path should use team-a token
	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://artifactory.example.com/api/npm/team-a-npm/@scope/pkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", teamAToken, "team-a path should use team-a token")

	// Request to team-b path should use team-b token, not team-a
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://artifactory.example.com/api/npm/team-b-npm/@scope/pkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", teamBToken, "team-b path should use team-b token")

	// Request to unrelated path should not be authenticated
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://artifactory.example.com/api/npm/team-c-npm/@scope/pkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "unrelated path should not match any credential")
}

func TestNPMRegistryHandlerProxyOnlyCredentials(t *testing.T) {
	handler := NewNPMRegistryHandler(config.Credentials{
		config.Credential{
			"type":       "npm_registry",
			"registry":   "https://npm.pkg.github.com",
			"token":      "x-access-token:automatic-token",
			"proxy-only": true,
		},
		config.Credential{
			"type":     "npm_registry",
			"registry": "https://npm.pkg.github.com/dependabot",
			"token":    "explicit-token",
		},
	}, testOIDCClient)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://npm.pkg.github.com/other/package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "x-access-token", "automatic-token", "host-only automatic credential")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://npm.pkg.github.com/other/package", nil)
	req.Header.Set("Authorization", authorizationPlaceholder)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "x-access-token", "automatic-token", "automatic credential replaces placeholder auth")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://npm.pkg.github.com/other/package", nil)
	req.Header.Set("Authorization", "Bearer request-token")
	req = handleRequestAndClose(handler, req, nil)
	assert.Equal(t, "Bearer request-token", req.Header.Get("Authorization"), "automatic credential preserves request auth")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://npm.pkg.github.com/dependabot/package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", "explicit-token", "path-specific explicit credential")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://npm.pkg.github.com/dependabot-attacker/package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "x-access-token", "automatic-token", "sibling path uses host-wide automatic credential")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://npm.pkg.github.example/other/package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "automatic credential host mismatch")
}
