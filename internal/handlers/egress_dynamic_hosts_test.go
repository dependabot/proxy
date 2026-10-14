package handlers

import (
	"net/http"
	"net/http/httptest"
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

func TestRegistryRedirectHosts_NotAddedWithoutECRCredential(t *testing.T) {
	h := newEgressHandlerWithCreds(config.Credentials{
		{"type": "docker_registry", "registry": "https://registry.internal.example.com"},
	})
	assert.NotNil(t, egressResult(t, h, "https://prod-eu-west-1-starport-layer-bucket.s3.eu-west-1.amazonaws.com/loot"),
		"layer bucket must not be allowed for a job with no ECR credential")
}

func TestRegistryRedirectHosts_PackagecloudDownloadCDNDerived(t *testing.T) {
	// packagecloud.io 302-redirects package downloads to a CloudFront
	// distribution that appears in no credential field.
	creds := config.Credentials{
		{"type": "python_index", "index-url": "https://packagecloud.io/acme/repo/pypi/simple"},
	}
	h := newEgressHandlerWithCreds(creds)

	assert.Nil(t, egressResult(t, h, "https://packagecloud.io/acme/repo/pypi/simple/pkg/"),
		"the configured packagecloud registry must be allowed")
	assert.Nil(t, egressResult(t, h, "https://d3fo0g5hm7lbuv.cloudfront.net/1358/1665/blobs/pkg.whl?Expires=1&Signature=x"),
		"the packagecloud download CDN must be allowed for a job with a packagecloud credential")

	for _, blocked := range []string{
		// Dynamic hosts are matched exactly, so no child or lookalike widens it.
		"https://evil.d3fo0g5hm7lbuv.cloudfront.net/loot",
		"https://d3fo0g5hm7lbuv.cloudfront.net.attacker.com/loot",
		// The shared CloudFront namespace stays closed.
		"https://cloudfront.net/loot",
		"https://d1ii4ma7ymllif.cloudfront.net/loot",
	} {
		assert.NotNil(t, egressResult(t, h, blocked), "must remain blocked: "+blocked)
	}
}

func TestRegistryRedirectHosts_PackagecloudMatchedExactly(t *testing.T) {
	// Only packagecloud.io itself opens the CDN, not a lookalike.
	assert.Equal(t,
		[]string{"d3fo0g5hm7lbuv.cloudfront.net"},
		registryRedirectHosts([]string{"packagecloud.io"}))
	assert.Equal(t,
		[]string{"d3fo0g5hm7lbuv.cloudfront.net"},
		registryRedirectHosts([]string{"packagecloud.io."}),
		"an absolute DNS name derives like its relative form")

	for _, host := range []string{
		"packagecloud.io.attacker.com",
		"evil.packagecloud.io",
		"packagecloud.com",
		"notpackagecloud.io",
	} {
		assert.Empty(t, registryRedirectHosts([]string{host}), "must derive nothing from %q", host)
	}
}

func TestRegistryRedirectHosts_PackagecloudCDNNotAllowedWithoutCredential(t *testing.T) {
	h := newEgressHandlerWithCreds(config.Credentials{
		{"type": "python_index", "index-url": "https://pypi.internal.example.com/simple"},
	})
	assert.NotNil(t, egressResult(t, h, "https://d3fo0g5hm7lbuv.cloudfront.net/loot"),
		"download CDN must not be allowed for a job with no packagecloud credential")
}

func TestRegistryRedirectHosts_GemfuryStorageDerived(t *testing.T) {
	// Gemfury endpoints redirect downloads to one Gemfury-owned bucket,
	// reachable on both its dualstack and plain accelerate endpoints.
	creds := config.Credentials{
		{"type": "python_index", "index-url": "https://pypi.fury.io/acme/"},
	}
	h := newEgressHandlerWithCreds(creds)

	assert.Nil(t, egressResult(t, h, "https://pypi.fury.io/acme/-/ver_x/pkg-1.0.0-py3-none-any.whl"),
		"the Gemfury registry itself must be allowed")
	for _, allowed := range []string{
		"https://gemfury.s3-accelerate.dualstack.amazonaws.com/gems/x/pkg_whl?X-Amz-Signature=x",
		"https://gemfury.s3-accelerate.amazonaws.com/gems/x/pkg_whl?X-Amz-Signature=x",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "Gemfury storage must be allowed: "+allowed)
	}

	for _, blocked := range []string{
		// Dynamic hosts are matched exactly, so no child or lookalike widens it.
		"https://evil.gemfury.s3-accelerate.dualstack.amazonaws.com/loot",
		"https://gemfuryx.s3-accelerate.dualstack.amazonaws.com/loot",
		// Only the accelerate endpoints are opened.
		"https://gemfury.s3.amazonaws.com/loot",
		// The shared parent namespace stays closed.
		"https://attacker.s3-accelerate.dualstack.amazonaws.com/loot",
		"https://attacker.s3-accelerate.amazonaws.com/loot",
	} {
		assert.NotNil(t, egressResult(t, h, blocked), "must remain blocked: "+blocked)
	}
}

func TestRegistryRedirectHosts_OnlyGemfuryHosts(t *testing.T) {
	gemfuryStorage := []string{
		"gemfury.s3-accelerate.dualstack.amazonaws.com",
		"gemfury.s3-accelerate.amazonaws.com",
	}

	for _, host := range []string{
		"pypi.fury.io",
		"npm.fury.io",
		"npm-proxy.fury.io",
		"gem.fury.io",
		"repo.fury.io",
		// An absolute DNS name derives like its relative form.
		"pypi.fury.io.",
	} {
		assert.Equal(t, gemfuryStorage, registryRedirectHosts([]string{host}),
			"must derive the Gemfury storage hosts from %q", host)
	}

	for _, host := range []string{
		"fury.io",               // apex is not a registry endpoint
		"pypi.fury.io.evil.com", // suffix must be fury.io
		"pypifury.io",
		"evil.com",
	} {
		assert.Empty(t, registryRedirectHosts([]string{host}), "must derive nothing from %q", host)
	}

	// Several Gemfury credentials yield one entry per storage host.
	assert.Equal(t,
		append([]string{"pypi.fury.io", "npm.fury.io"}, gemfuryStorage...),
		dynamicHosts(config.Credentials{
			{"type": "python_index", "index-url": "https://pypi.fury.io/acme/"},
			{"type": "npm_registry", "registry": "https://npm.fury.io/acme/"},
		}))
}

func TestRegistryRedirectHosts_NotAddedWithoutGemfuryCredential(t *testing.T) {
	h := newEgressHandlerWithCreds(config.Credentials{
		{"type": "python_index", "index-url": "https://pypi.internal.example.com/simple"},
	})
	for _, blocked := range []string{
		"https://gemfury.s3-accelerate.dualstack.amazonaws.com/gems/x/loot",
		"https://gemfury.s3-accelerate.amazonaws.com/gems/x/loot",
	} {
		assert.NotNil(t, egressResult(t, h, blocked),
			"Gemfury storage must not be allowed for a job with no Gemfury credential: "+blocked)
	}
}

func TestRegistryRedirectPaths_GemfuryPathStyleS3(t *testing.T) {
	// Gemfury also redirects some downloads to its bucket in path-style form on
	// the shared S3 endpoint (dependabot/proxy#308). Only that bucket's prefix
	// may be reached, never the host as a whole.
	h := newEgressHandlerWithCreds(config.Credentials{
		{"type": "python_index", "index-url": "https://pypi.fury.io/acme/"},
	})

	for _, allowed := range []string{
		"https://s3.amazonaws.com/gemfury/gems/abc123/pkg-1.0.0-py3-none-any.whl?x-acct=acme&X-Amz-Signature=x",
		"https://s3.amazonaws.com:443/gemfury/gems/abc123/pkg-1.0.0%2Blocal-py3-none-any.whl",
		"https://s3.amazonaws.com./gemfury/gems/abc123/pkg.whl",
	} {
		assert.Nil(t, egressResult(t, h, allowed), "Gemfury path-style download must be allowed: "+allowed)
	}

	for _, blocked := range []string{
		// Other buckets and the bare host stay closed.
		"https://s3.amazonaws.com/",
		"https://s3.amazonaws.com/attacker/loot",
		"https://s3.amazonaws.com/gemfury",
		"https://s3.amazonaws.com/gemfuryx/loot",
		"https://s3.amazonaws.com/gemfury-attacker/loot",
		"https://s3.amazonaws.com/GEMFURY/loot",
		// The prefix cannot be escaped with dot segments or encoded separators.
		"https://s3.amazonaws.com/gemfury/../attacker/loot",
		"https://s3.amazonaws.com/gemfury/%2e%2e/attacker/loot",
		"https://s3.amazonaws.com/gemfury%2F..%2Fattacker/loot",
		"https://s3.amazonaws.com/gemfury%2Floot",
		"https://s3.amazonaws.com/gemfury/gems/..%5C..%5Cattacker/loot",
		"https://s3.amazonaws.com/gemfury/./loot",
		// Only the exact host gets the path rule.
		"https://evil.s3.amazonaws.com/gemfury/loot",
		"https://s3.us-east-1.amazonaws.com/gemfury/loot",
		"https://s3.amazonaws.com.evil.com/gemfury/loot",
	} {
		assert.NotNil(t, egressResult(t, h, blocked), "must remain blocked: "+blocked)
	}

	for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodDelete} {
		req := httptest.NewRequestWithContext(t.Context(), method, "https://s3.amazonaws.com/gemfury/gems/x/loot", nil)
		_, resp := h.HandleRequest(req, nil)
		require.NotNil(t, resp, method+" must be blocked")
		mustClose(resp.Body)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodHead, "https://s3.amazonaws.com/gemfury/gems/x/pkg.whl", nil)
	_, resp := h.HandleRequest(req, nil)
	assert.Nil(t, resp, "HEAD must be allowed")
}

func TestRegistryRedirectPaths_NotAddedWithoutGemfuryCredential(t *testing.T) {
	h := newEgressHandlerWithCreds(config.Credentials{
		{"type": "python_index", "index-url": "https://pypi.internal.example.com/simple"},
	})
	assert.NotNil(t, egressResult(t, h, "https://s3.amazonaws.com/gemfury/gems/x/loot"),
		"Gemfury path-style storage must not be allowed for a job with no Gemfury credential")

	assert.Empty(t, registryRedirectPaths([]string{"fury.io", "pypi.fury.io.evil.com", "evil.com"}))
	assert.Equal(t,
		[]derivedPath{{Host: "s3.amazonaws.com", PathPrefix: "/gemfury/"}},
		registryRedirectPaths([]string{"pypi.fury.io", "npm.fury.io", "pypi.fury.io."}),
		"several Gemfury credentials yield one path rule")
}

func TestValidateRegistryRedirectDerivations_PathPrefixes(t *testing.T) {
	valid := registryRedirectDerivation{
		CredentialHost: ".fury.io",
		DerivedPaths:   []derivedPath{{Host: "s3.amazonaws.com", PathPrefix: "/gemfury/"}},
	}
	assert.NoError(t, validateRegistryRedirectDerivations([]registryRedirectDerivation{valid}),
		"derived_paths alone is a valid derivation")

	for name, p := range map[string]derivedPath{
		"empty host":          {Host: "", PathPrefix: "/gemfury/"},
		"glob host":           {Host: "*.amazonaws.com", PathPrefix: "/gemfury/"},
		"leading-dot host":    {Host: ".amazonaws.com", PathPrefix: "/gemfury/"},
		"empty prefix":        {Host: "s3.amazonaws.com", PathPrefix: ""},
		"root prefix":         {Host: "s3.amazonaws.com", PathPrefix: "/"},
		"no trailing slash":   {Host: "s3.amazonaws.com", PathPrefix: "/gemfury"},
		"no leading slash":    {Host: "s3.amazonaws.com", PathPrefix: "gemfury/"},
		"dot segment":         {Host: "s3.amazonaws.com", PathPrefix: "/gemfury/../"},
		"double slash":        {Host: "s3.amazonaws.com", PathPrefix: "//gemfury/"},
		"percent-encoded":     {Host: "s3.amazonaws.com", PathPrefix: "/gem%66ury/"},
		"glob in prefix":      {Host: "s3.amazonaws.com", PathPrefix: "/gem*/"},
		"backslash in prefix": {Host: "s3.amazonaws.com", PathPrefix: "/gem\\fury/"},
	} {
		d := registryRedirectDerivation{CredentialHost: ".fury.io", DerivedPaths: []derivedPath{p}}
		assert.Errorf(t, validateRegistryRedirectDerivations([]registryRedirectDerivation{d}), "must reject %s", name)
	}
}
