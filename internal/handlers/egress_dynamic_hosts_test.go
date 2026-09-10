package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/config"
)

func TestHostFromValue(t *testing.T) {
	cases := map[string]string{
		"https://registry.example.com/path":  "registry.example.com",
		"registry.example.com":               "registry.example.com",
		"registry.example.com:8080":          "registry.example.com",
		"registry.example.com/foo/bar":       "registry.example.com",
		"https://user:pass@host.example.com": "host.example.com",
		"HTTPS://Registry.Example.COM":       "registry.example.com",
		"":                                   "",
		"   ":                                "",
	}
	for in, want := range cases {
		assert.Equal(t, want, hostFromValue(in), "hostFromValue(%q)", in)
	}
}

func TestCredentialHosts_ConfiguredRegistriesAllowed(t *testing.T) {
	creds := config.Credentials{
		{"type": "npm_registry", "registry": "https://npm.internal.example.com"},
		{"type": "python_index", "index-url": "https://pypi.internal.example.com/simple"},
		{"type": "maven_repository", "url": "https://maven.internal.example.com/repo"},
		{"type": "git_source", "host": "git.internal.example.com"},
	}
	h := newEgressHandlerWithCreds(creds)

	for _, host := range []string{
		"npm.internal.example.com",
		"pypi.internal.example.com",
		"maven.internal.example.com",
		"git.internal.example.com",
	} {
		assert.Nil(t, egressResult(t, h, "https://"+host+"/x"),
			"configured registry %s must be allowed", host)
	}

	// A host that is not configured and not a default is still blocked.
	assert.NotNil(t, egressResult(t, h, "https://evil.example.com/steal"),
		"non-configured host must still be blocked")
}

func TestOIDCExchangeHosts_Azure(t *testing.T) {
	creds := config.Credentials{
		{
			"type":      "nuget_feed",
			"url":       "https://pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json",
			"tenant-id": "tenant-123",
			"client-id": "client-456",
		},
	}
	hosts := oidcExchangeHosts(creds)
	assert.Contains(t, hosts, "login.microsoftonline.com")

	// End-to-end: both the token endpoint and the feed host are allowed.
	h := newEgressHandlerWithCreds(creds)
	assert.Nil(t, egressResult(t, h, "https://login.microsoftonline.com/tenant-123/oauth2/v2.0/token"))
	assert.Nil(t, egressResult(t, h, "https://pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json"))
}

func TestOIDCExchangeHosts_ByProvider(t *testing.T) {
	require.ElementsMatch(t, []string{"sts.amazonaws.com"}, oidcExchangeHosts(config.Credentials{
		{"aws-region": "us-east-1", "role-name": "dependabot"},
	}))
	require.ElementsMatch(t,
		[]string{"sts.googleapis.com", "iamcredentials.googleapis.com", "www.googleapis.com"},
		oidcExchangeHosts(config.Credentials{
			{"workload-identity-provider": "projects/1/locations/global/workloadIdentityPools/p/providers/gh"},
		}),
	)
	require.ElementsMatch(t, []string{"api.cloudsmith.io"}, oidcExchangeHosts(config.Credentials{
		{"organization": "acme", "service-slug": "dependabot"},
	}))
	// api-host override is honoured.
	require.ElementsMatch(t, []string{"api.eu.cloudsmith.io"}, oidcExchangeHosts(config.Credentials{
		{"organization": "acme", "service-slug": "dependabot", "api-host": "api.eu.cloudsmith.io"},
	}))
	// Non-OIDC credentials contribute no exchange endpoints.
	assert.Empty(t, oidcExchangeHosts(config.Credentials{
		{"type": "npm_registry", "registry": "https://npm.example.com"},
	}))
}

func TestDynamicHosts_Deduplicates(t *testing.T) {
	creds := config.Credentials{
		{"type": "npm_registry", "registry": "https://npm.example.com"},
		{"type": "npm_registry", "url": "https://npm.example.com/other"},
	}
	got := dynamicHosts(creds)
	assert.Equal(t, []string{"npm.example.com"}, got)
}
