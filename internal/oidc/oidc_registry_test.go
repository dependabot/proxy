package oidc

import (
	"net/http/httptest"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/config"
)

func setupOIDCEnv(t *testing.T) {
	t.Helper()
	t.Setenv(envActionsIDTokenRequestURL, "https://token.actions.example.com")
	t.Setenv(envActionsIDTokenRequestToken, "sometoken")
}

func mockAzureOIDC(t *testing.T, tenantID, token string) {
	t.Helper()
	httpmock.RegisterResponder("GET", "https://token.actions.example.com",
		httpmock.NewStringResponder(200, `{"count": 1, "value": "sometoken"}`))
	httpmock.RegisterResponder("POST",
		"https://login.microsoftonline.com/"+tenantID+"/oauth2/v2.0/token",
		httpmock.NewStringResponder(200, `{
			"access_token": "`+token+`",
			"expires_in": 3600,
			"token_type": "Bearer"
		}`))
}

func azureCred(tenantID, clientID string) config.Credential {
	return config.Credential{
		"type":      "test_registry",
		"tenant-id": tenantID,
		"client-id": clientID,
	}
}

func azureCredWithURL(tenantID, clientID, url string) config.Credential {
	cred := azureCred(tenantID, clientID)
	cred["url"] = url
	return cred
}

func azureCredWithRegistry(tenantID, clientID, registry string) config.Credential {
	cred := azureCred(tenantID, clientID)
	cred["registry"] = registry
	return cred
}

func TestOIDCRegistry_Register_SingleCredential(t *testing.T) {
	setupOIDCEnv(t)
	r := NewOIDCRegistry()

	cred := azureCredWithURL("tenant-1", "client-1", "https://registry.example.com/packages")
	oidcCred, key, ok := r.Register(cred, []string{"url"}, "test registry")

	assert.True(t, ok, "should register successfully")
	assert.NotNil(t, oidcCred)
	assert.Equal(t, "https://registry.example.com/packages", key)
}

func TestOIDCRegistry_Register_URLFieldPriority(t *testing.T) {
	setupOIDCEnv(t)
	r := NewOIDCRegistry()

	cred := config.Credential{
		"type":      "test_registry",
		"tenant-id": "tenant-1",
		"client-id": "client-1",
		"registry":  "https://registry.example.com/from-registry",
		"url":       "https://registry.example.com/from-url",
	}

	_, key, ok := r.Register(cred, []string{"registry", "url"}, "test registry")

	assert.True(t, ok, "should register successfully")
	assert.Equal(t, "https://registry.example.com/from-registry", key, "should prefer first urlField")
}

func TestOIDCRegistry_Register_FallsBackToHost(t *testing.T) {
	setupOIDCEnv(t)
	r := NewOIDCRegistry()

	cred := config.Credential{
		"type":      "test_registry",
		"tenant-id": "tenant-1",
		"client-id": "client-1",
		"host":      "registry.example.com",
	}

	_, key, ok := r.Register(cred, []string{"url"}, "test registry")

	assert.True(t, ok, "should register with host fallback")
	assert.Equal(t, "registry.example.com", key)
}

func TestOIDCRegistry_Register_NotOIDC(t *testing.T) {
	// Ensure OIDC env vars are not set — CreateOIDCCredential will return nil
	t.Setenv(envActionsIDTokenRequestURL, "")
	t.Setenv(envActionsIDTokenRequestToken, "")

	r := NewOIDCRegistry()
	cred := config.Credential{
		"type": "test_registry",
		"url":  "https://registry.example.com",
	}

	oidcCred, key, ok := r.Register(cred, []string{"url"}, "test registry")

	assert.False(t, ok)
	assert.Nil(t, oidcCred)
	assert.Empty(t, key)
}

func TestOIDCRegistry_Register_NoKeyAvailable(t *testing.T) {
	setupOIDCEnv(t)
	r := NewOIDCRegistry()

	// Credential with OIDC params but no URL or host
	cred := config.Credential{
		"type":      "test_registry",
		"tenant-id": "tenant-1",
		"client-id": "client-1",
	}

	oidcCred, key, ok := r.Register(cred, []string{"url"}, "test registry")

	assert.False(t, ok, "should not register without a key")
	assert.NotNil(t, oidcCred, "credential was created but couldn't be stored")
	assert.Empty(t, key)
}

func TestOIDCRegistry_TryAuth_SingleCredential(t *testing.T) {
	setupOIDCEnv(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	mockAzureOIDC(t, "tenant-1", "__test_token__")

	r := NewOIDCRegistry()
	cred := azureCredWithURL("tenant-1", "client-1", "https://registry.example.com/packages")
	r.Register(cred, []string{"url"}, "test registry")

	req := httptest.NewRequest("GET", "https://registry.example.com/packages/some-package", nil)
	ok := r.TryAuth(req, nil)

	assert.True(t, ok, "should authenticate")
	assert.Equal(t, "Bearer __test_token__", req.Header.Get("Authorization"))
}

func TestOIDCRegistry_TryAuth_SameHostDifferentPaths_NoCollision(t *testing.T) {
	setupOIDCEnv(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	mockAzureOIDC(t, "tenant-A", "token-feed-A")
	mockAzureOIDC(t, "tenant-B", "token-feed-B")

	r := NewOIDCRegistry()

	// Two registries on the same host with different paths
	credA := azureCredWithURL("tenant-A", "client-A",
		"https://pkgs.dev.azure.com/org/_packaging/feed-A/npm/registry/")
	credB := azureCredWithURL("tenant-B", "client-B",
		"https://pkgs.dev.azure.com/org/_packaging/feed-B/npm/registry/")

	_, keyA, okA := r.Register(credA, []string{"url"}, "test registry")
	_, keyB, okB := r.Register(credB, []string{"url"}, "test registry")

	require.True(t, okA, "feed-A should register")
	require.True(t, okB, "feed-B should register")
	assert.NotEqual(t, keyA, keyB, "keys should be different")

	// Request to feed-A should get feed-A's token
	reqA := httptest.NewRequest("GET",
		"https://pkgs.dev.azure.com/org/_packaging/feed-A/npm/registry/@scope/package", nil)
	ok := r.TryAuth(reqA, nil)
	assert.True(t, ok, "feed-A request should be authenticated")
	assert.Equal(t, "Bearer token-feed-A", reqA.Header.Get("Authorization"),
		"feed-A request should get feed-A's token")

	// Request to feed-B should get feed-B's token
	reqB := httptest.NewRequest("GET",
		"https://pkgs.dev.azure.com/org/_packaging/feed-B/npm/registry/@scope/package", nil)
	ok = r.TryAuth(reqB, nil)
	assert.True(t, ok, "feed-B request should be authenticated")
	assert.Equal(t, "Bearer token-feed-B", reqB.Header.Get("Authorization"),
		"feed-B request should get feed-B's token")
}

func TestOIDCRegistry_TryAuth_HostOnlyMatchesAnyPath(t *testing.T) {
	setupOIDCEnv(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	mockAzureOIDC(t, "tenant-1", "__test_token__")

	r := NewOIDCRegistry()

	// Register with host only (no path)
	cred := config.Credential{
		"type":      "test_registry",
		"tenant-id": "tenant-1",
		"client-id": "client-1",
		"host":      "registry.example.com",
	}
	r.Register(cred, []string{"url"}, "test registry")

	// Should match any path on that host
	req := httptest.NewRequest("GET", "https://registry.example.com/any/path/here", nil)
	ok := r.TryAuth(req, nil)

	assert.True(t, ok, "host-only credential should match any path")
	assert.Equal(t, "Bearer __test_token__", req.Header.Get("Authorization"))
}

func TestOIDCRegistry_TryAuth_NoMatch(t *testing.T) {
	setupOIDCEnv(t)
	r := NewOIDCRegistry()

	cred := azureCredWithURL("tenant-1", "client-1", "https://registry.example.com/packages")
	r.Register(cred, []string{"url"}, "test registry")

	// Request to a different host
	req := httptest.NewRequest("GET", "https://other.example.com/packages/something", nil)
	ok := r.TryAuth(req, nil)

	assert.False(t, ok, "should not match different host")
	assert.Empty(t, req.Header.Get("Authorization"))
}

func TestOIDCRegistry_TryAuth_WrongPathNoMatch(t *testing.T) {
	setupOIDCEnv(t)
	r := NewOIDCRegistry()

	cred := azureCredWithURL("tenant-1", "client-1",
		"https://pkgs.dev.azure.com/org/_packaging/feed-A/npm/registry/")
	r.Register(cred, []string{"url"}, "test registry")

	// Request to same host but different feed path
	req := httptest.NewRequest("GET",
		"https://pkgs.dev.azure.com/org/_packaging/feed-B/npm/registry/@scope/pkg", nil)
	ok := r.TryAuth(req, nil)

	assert.False(t, ok, "should not match different path")
	assert.Empty(t, req.Header.Get("Authorization"))
}

func TestOIDCRegistry_RegisterURL(t *testing.T) {
	setupOIDCEnv(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	mockAzureOIDC(t, "tenant-1", "__test_token__")

	r := NewOIDCRegistry()

	// Register primary URL
	cred := azureCredWithURL("tenant-1", "client-1", "https://nuget.example.com/v3/index.json")
	oidcCred, _, ok := r.Register(cred, []string{"url"}, "nuget feed")
	require.True(t, ok)

	// Register discovered URL (like nuget does)
	r.RegisterURL("https://nuget.example.com/v3/package-content", oidcCred, "nuget resource")

	// Request to discovered URL should be authenticated
	req := httptest.NewRequest("GET",
		"https://nuget.example.com/v3/package-content/some-package/1.0.0", nil)
	ok = r.TryAuth(req, nil)

	assert.True(t, ok, "discovered URL should be authenticated")
	assert.Equal(t, "Bearer __test_token__", req.Header.Get("Authorization"))
}

func TestOIDCRegistry_TryAuth_PortMismatch(t *testing.T) {
	setupOIDCEnv(t)
	r := NewOIDCRegistry()

	cred := azureCredWithURL("tenant-1", "client-1", "https://registry.example.com:8443/packages")
	r.Register(cred, []string{"url"}, "test registry")

	// Request on default port (443) should not match cred on port 8443
	req := httptest.NewRequest("GET", "https://registry.example.com/packages/something", nil)
	ok := r.TryAuth(req, nil)

	assert.False(t, ok, "should not match different port")
}

func TestOIDCRegistry_Register_RegistryField(t *testing.T) {
	setupOIDCEnv(t)
	r := NewOIDCRegistry()

	cred := azureCredWithRegistry("tenant-1", "client-1", "ghcr.io")
	_, key, ok := r.Register(cred, []string{"registry"}, "docker registry")

	assert.True(t, ok)
	assert.Equal(t, "ghcr.io", key)
}

func TestOIDCRegistry_TryAuth_PathSpecificBeatsHostOnly(t *testing.T) {
	setupOIDCEnv(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	mockAzureOIDC(t, "tenant-1", "__host_only_token__")
	mockAzureOIDC(t, "tenant-2", "__path_specific_token__")

	r := NewOIDCRegistry()

	hostOnlyCred := config.Credential{
		"type":      "test_registry",
		"tenant-id": "tenant-1",
		"client-id": "client-1",
		"host":      "registry.example.com",
	}
	pathSpecificCred := azureCredWithURL("tenant-2", "client-2", "https://registry.example.com/packages/private")

	// Register the less specific match first to verify the most specific wins
	r.Register(hostOnlyCred, []string{"url"}, "test registry")
	r.Register(pathSpecificCred, []string{"url"}, "test registry")

	req := httptest.NewRequest("GET", "https://registry.example.com/packages/private/module.tgz", nil)
	ok := r.TryAuth(req, nil)

	assert.True(t, ok, "path-specific credential should match request")
	assert.Equal(t, "Bearer __path_specific_token__", req.Header.Get("Authorization"))
}

func TestOIDCRegistry_TryAuth_LongestPathPrefixWins(t *testing.T) {
	setupOIDCEnv(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	mockAzureOIDC(t, "tenant-1", "__short_prefix_token__")
	mockAzureOIDC(t, "tenant-2", "__long_prefix_token__")

	r := NewOIDCRegistry()

	shortPrefixCred := azureCredWithURL("tenant-1", "client-1", "https://registry.example.com/packages")
	longPrefixCred := azureCredWithURL("tenant-2", "client-2", "https://registry.example.com/packages/private")

	// Register the shorter prefix first to verify specificity over insertion order
	r.Register(shortPrefixCred, []string{"url"}, "test registry")
	r.Register(longPrefixCred, []string{"url"}, "test registry")

	req := httptest.NewRequest("GET", "https://registry.example.com/packages/private/module.tgz", nil)
	ok := r.TryAuth(req, nil)

	assert.True(t, ok, "longer path prefix should match request")
	assert.Equal(t, "Bearer __long_prefix_token__", req.Header.Get("Authorization"))
}

func TestOIDCRegistry_TryAuth_CaseInsensitiveHost(t *testing.T) {
	setupOIDCEnv(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	mockAzureOIDC(t, "tenant-1", "__test_token__")

	r := NewOIDCRegistry()

	cred := azureCredWithURL("tenant-1", "client-1", "https://Registry.Example.COM/packages")
	r.Register(cred, []string{"url"}, "test registry")

	// Request with different casing should still match
	req := httptest.NewRequest("GET", "https://REGISTRY.EXAMPLE.COM/packages/something", nil)
	ok := r.TryAuth(req, nil)

	assert.True(t, ok, "host matching should be case-insensitive")
	assert.Equal(t, "Bearer __test_token__", req.Header.Get("Authorization"))
}

func mockCloudsmithOIDC(t *testing.T, namespace, token string) {
	t.Helper()
	httpmock.RegisterResponder("GET", "https://token.actions.example.com",
		httpmock.NewStringResponder(200, `{"count": 1, "value": "sometoken"}`))
	httpmock.RegisterResponder("POST",
		"https://api.cloudsmith.io/openid/"+namespace+"/",
		httpmock.NewStringResponder(200, `{"token": "`+token+`"}`))
}

func cloudsmithCred(namespace, serviceSlug, audience, url string) config.Credential {
	return config.Credential{
		"type":              "test_registry",
		"oidc-namespace":    namespace,
		"oidc-service-slug": serviceSlug,
		"oidc-audience":     audience,
		"url":               url,
	}
}

func TestOIDCRegistry_TryAuth_Cloudsmith_UsesAPIKey(t *testing.T) {
	setupOIDCEnv(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	mockCloudsmithOIDC(t, "my-org", "__cs_token__")

	r := NewOIDCRegistry()

	cred := cloudsmithCred("my-org", "my-service", "https://cloudsmith.io", "https://dl.cloudsmith.io/basic/my-org/my-repo")
	r.Register(cred, []string{"url"}, "test registry")

	req := httptest.NewRequest("GET", "https://dl.cloudsmith.io/basic/my-org/my-repo/some-package", nil)
	ok := r.TryAuth(req, nil)

	assert.True(t, ok, "cloudsmith OIDC should authenticate")
	assert.Equal(t, "__cs_token__", req.Header.Get("X-Api-Key"), "cloudsmith should use X-Api-Key")
	assert.Empty(t, req.Header.Get("Authorization"), "cloudsmith should not set Authorization")
}

func TestOIDCRegistry_Register_IndexURLField(t *testing.T) {
	setupOIDCEnv(t)
	r := NewOIDCRegistry()

	cred := azureCred("tenant-1", "client-1")
	cred["index-url"] = "https://pkgs.dev.azure.com/org/_packaging/feed/pypi/simple"

	_, key, ok := r.Register(cred, []string{"index-url", "url"}, "python index")

	assert.True(t, ok)
	assert.Equal(t, "https://pkgs.dev.azure.com/org/_packaging/feed/pypi/simple", key)
}

func TestOIDCRegistry_TryAuth_URLWithoutProtocol(t *testing.T) {
	setupOIDCEnv(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	mockAzureOIDC(t, "tenant-1", "__test_token__")

	r := NewOIDCRegistry()

	cred := azureCred("tenant-1", "client-1")
	cred["url"] = "registry.example.com/packages"
	r.Register(cred, []string{"url"}, "test registry")

	req := httptest.NewRequest("GET", "https://registry.example.com/packages/something", nil)
	ok := r.TryAuth(req, nil)

	assert.True(t, ok, "URL without protocol should be handled by ParseURLLax")
	assert.Equal(t, "Bearer __test_token__", req.Header.Get("Authorization"))
}

func TestOIDCRegistry_RegisterURL_MultipleOnSameHost(t *testing.T) {
	setupOIDCEnv(t)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	mockAzureOIDC(t, "tenant-1", "__test_token__")

	r := NewOIDCRegistry()

	cred := azureCredWithURL("tenant-1", "client-1", "https://nuget.example.com/v3/index.json")
	oidcCred, _, ok := r.Register(cred, []string{"url"}, "nuget feed")
	require.True(t, ok)

	// Register additional discovered resource URLs (nuget pattern)
	r.RegisterURL("https://nuget.example.com/v3/package-content", oidcCred, "nuget resource")
	r.RegisterURL("https://nuget.example.com/v3/registrations", oidcCred, "nuget resource")

	// All three paths should authenticate
	for _, path := range []string{"/v3/index.json", "/v3/package-content/Some.Package/1.0.0", "/v3/registrations/some.package/index.json"} {
		req := httptest.NewRequest("GET", "https://nuget.example.com"+path, nil)
		ok := r.TryAuth(req, nil)
		assert.True(t, ok, "should authenticate: "+path)
		assert.Equal(t, "Bearer __test_token__", req.Header.Get("Authorization"))
	}
}

func TestOIDCRegistry_Register_NoDuplicateEntries(t *testing.T) {
	setupOIDCEnv(t)

	r := NewOIDCRegistry()

	cred1 := azureCredWithURL("tenant-1", "client-1", "https://registry.example.com/packages")
	cred2 := azureCredWithURL("tenant-2", "client-2", "https://registry.example.com/packages")

	r.Register(cred1, []string{"url"}, "test registry")
	r.Register(cred2, []string{"url"}, "test registry")

	r.mutex.RLock()
	entries := r.byHost["registry.example.com"]
	r.mutex.RUnlock()

	assert.Equal(t, 1, len(entries), "duplicate path+port should not create a second entry")
}
