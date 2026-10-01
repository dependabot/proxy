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

func TestRegistryRedirectHosts_ECRStarportBucketDerived(t *testing.T) {
	// Private ECR 307-redirects layer downloads to a per-region AWS-owned S3
	// bucket that appears in no credential field, so it is derived from the
	// region named by the job's own ECR credential.
	creds := config.Credentials{
		{"type": "docker_registry", "registry": "123456789012.dkr.ecr.eu-west-1.amazonaws.com"},
	}
	h := newEgressHandlerWithCreds(creds)

	assert.Nil(t, egressResult(t, h, "https://123456789012.dkr.ecr.eu-west-1.amazonaws.com/v2/chart/manifests/1.0.0"),
		"the ECR registry itself must be allowed")
	assert.Nil(t, egressResult(t, h, "https://prod-eu-west-1-starport-layer-bucket.s3.eu-west-1.amazonaws.com/blob?X-Amz-Signature=x"),
		"the ECR layer bucket for the credential's region must be allowed")

	for _, blocked := range []string{
		// Only the region the job actually uses is opened.
		"https://prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com/loot",
		// Dynamic hosts are matched exactly, so no child or lookalike widens it.
		"https://evil.prod-eu-west-1-starport-layer-bucket.s3.eu-west-1.amazonaws.com/loot",
		"https://prod-eu-west-1-starport-layer-bucket.s3.amazonaws.com/loot",
		// The shared parent namespace stays closed.
		"https://attacker-bucket.s3.eu-west-1.amazonaws.com/loot",
	} {
		assert.NotNil(t, egressResult(t, h, blocked), "must remain blocked: "+blocked)
	}
}

func TestRegistryRedirectHosts_OnlyCanonicalECRHosts(t *testing.T) {
	// The region is interpolated into an allowlist entry, so the pattern must
	// not match anything an attacker-supplied credential could bend.
	none := []string{
		"public.ecr.aws",                                  // public ECR has no starport backend
		"12345.dkr.ecr.eu-west-1.amazonaws.com",           // account id must be 12 digits
		"123456789012.dkr.ecr.amazonaws.com",              // missing region
		"123456789012.dkr.ecr.a.b.amazonaws.com",          // region must be a single label
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com.cn", // different partition
		"123456789012.dkr.ecr.eu-west-1.evil.com",         // suffix must be amazonaws.com
		"evil.com",
	}
	for _, h := range none {
		assert.Empty(t, registryRedirectHosts([]string{h}), "must derive nothing from %q", h)
	}

	assert.Equal(t,
		[]string{"prod-us-east-2-starport-layer-bucket.s3.us-east-2.amazonaws.com"},
		registryRedirectHosts([]string{"123456789012.dkr.ecr.us-east-2.amazonaws.com"}))
}

func TestRegistryRedirectHosts_GemfuryStorageDerived(t *testing.T) {
	// Gemfury 302-redirects package downloads from every registry endpoint to a
	// single Gemfury-owned S3 bucket via pre-signed URLs, so the bucket is
	// derived from the job's own Gemfury credential.
	creds := config.Credentials{
		{"type": "python_index", "index-url": "https://pypi.fury.io/acme/"},
	}
	h := newEgressHandlerWithCreds(creds)

	assert.Nil(t, egressResult(t, h, "https://pypi.fury.io/acme/-/ver_x/pkg-1.0.0-py3-none-any.whl"),
		"the Gemfury registry itself must be allowed")
	assert.Nil(t, egressResult(t, h, "https://gemfury.s3-accelerate.dualstack.amazonaws.com/gems/x/pkg_whl?X-Amz-Signature=x"),
		"the Gemfury storage bucket must be allowed")

	for _, blocked := range []string{
		// Dynamic hosts are matched exactly, so no child or lookalike widens it.
		"https://evil.gemfury.s3-accelerate.dualstack.amazonaws.com/loot",
		"https://gemfuryx.s3-accelerate.dualstack.amazonaws.com/loot",
		"https://gemfury.s3.amazonaws.com/loot",
		// The shared parent namespace stays closed.
		"https://attacker.s3-accelerate.dualstack.amazonaws.com/loot",
	} {
		assert.NotNil(t, egressResult(t, h, blocked), "must remain blocked: "+blocked)
	}
}

func TestRegistryRedirectHosts_OnlyGemfuryHosts(t *testing.T) {
	for _, h := range []string{
		"pypi.fury.io",
		"npm.fury.io",
		"npm-proxy.fury.io",
		"gem.fury.io",
	} {
		assert.Equal(t, []string{gemfuryStorageHost}, registryRedirectHosts([]string{h}),
			"must derive the Gemfury bucket from %q", h)
	}

	for _, h := range []string{
		"fury.io",               // apex is not a registry endpoint
		"pypi.fury.io.evil.com", // suffix must be fury.io
		"pypifury.io",
		"evil.com",
	} {
		assert.Empty(t, registryRedirectHosts([]string{h}), "must derive nothing from %q", h)
	}

	// Several Gemfury credentials still yield a single entry.
	assert.Equal(t, []string{"pypi.fury.io", "npm.fury.io", gemfuryStorageHost}, dynamicHosts(config.Credentials{
		{"type": "python_index", "index-url": "https://pypi.fury.io/acme/"},
		{"type": "npm_registry", "registry": "https://npm.fury.io/acme/"},
	}))
}

func TestRegistryRedirectHosts_NotAddedWithoutGemfuryCredential(t *testing.T) {
	h := newEgressHandlerWithCreds(config.Credentials{
		{"type": "python_index", "index-url": "https://pypi.internal.example.com/simple"},
	})
	assert.NotNil(t, egressResult(t, h, "https://gemfury.s3-accelerate.dualstack.amazonaws.com/gems/x/loot"),
		"Gemfury bucket must not be allowed for a job with no Gemfury credential")
}

func TestRegistryRedirectHosts_NotAddedWithoutECRCredential(t *testing.T) {
	h := newEgressHandlerWithCreds(config.Credentials{
		{"type": "docker_registry", "registry": "https://registry.internal.example.com"},
	})
	assert.NotNil(t, egressResult(t, h, "https://prod-eu-west-1-starport-layer-bucket.s3.eu-west-1.amazonaws.com/loot"),
		"layer bucket must not be allowed for a job with no ECR credential")
}
