package handlers

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/elazarl/goproxy"
	"github.com/jarcoal/httpmock"
	"github.com/stackrox/docker-registry-client/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/config"
)

type ecrContextKey struct{}

func TestDockerRegistryHandler(t *testing.T) {
	hubUser := "solomon"
	hubPassword := "hyk35"
	bigCoUser := "taylor"
	bigCoPassword := "sw1ft"
	ecrKeyID := "AK1234567899"
	ecrSecretKey := "BigLongAWSSecretKey"
	ecrDockerUser := "AWS"
	ecrDockerPassword := "BigLongGeneratedRegistryPassword"
	credentials := config.Credentials{
		config.Credential{
			"type":     "docker_registry",
			"registry": "registry.hub.docker.com",
			"username": hubUser,
			"password": hubPassword,
		},
		config.Credential{
			"type":     "docker_registry",
			"registry": "docker.bigco.com",
			"username": bigCoUser,
			"password": bigCoPassword,
		},
		config.Credential{
			"type":     "docker_registry",
			"registry": "123456789123.dkr.ecr.us-east-2.amazonaws.com:443",
			"username": ecrKeyID,
			"password": ecrSecretKey,
		},
		config.Credential{
			"type":     "docker_registry",
			"registry": "nexus.someco.com",
			"username": hubUser,
			"password": hubPassword,
		},
		config.Credential{
			"type":     "docker_registry",
			"url":      "https://example.com:443/dependabot/core",
			"username": hubUser,
			"password": hubPassword,
		},
	}
	mockECR := &mockECRClient{user: ecrDockerUser, token: ecrDockerPassword}
	httpClient := &http.Client{Transport: &http.Transport{}, Timeout: testOIDCClient.Timeout}
	var factoryContext context.Context
	getECRClient := func(ctx context.Context, region, keyID, secretKey string, client *http.Client) (ecrClient, error) {
		factoryContext = ctx
		assert.Same(t, httpClient, client, "ECR uses the bounded handler client")
		assert.Equal(t, "us-east-2", region, "ecr region is parsed from the registry host")
		assert.Equal(t, ecrKeyID, keyID, "docker username is used as the aws access key id")
		assert.Equal(t, ecrSecretKey, secretKey, "docker password is used as the aws secret access key")
		return mockECR, nil
	}
	handler := NewDockerRegistryHandler(credentials, httpClient, getECRClient)

	// Regular private registry
	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://registry.hub.docker.com/v2/my-repo/manifests/latest", nil)
	proxyCtx := &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, proxyCtx)
	rt, ok := proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.True(t, ok, "request is assigned a docker registry transport")
	trans := rt.transport.(*registry.BasicTransport)
	assert.Equal(t, hubUser, trans.Username, "correct username is set")
	assert.Equal(t, hubPassword, trans.Password, "correct password is set")

	// Registry using URL not registry key
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://example.com/v2/dependabot/core/manifests/latest", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, proxyCtx)
	rt, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.True(t, ok, "request is assigned a docker registry transport")
	trans = rt.transport.(*registry.BasicTransport)
	assert.Equal(t, hubUser, trans.Username, "correct username is set")
	assert.Equal(t, hubPassword, trans.Password, "correct password is set")
	assert.Equal(t, "https://example.com/v2/dependabot/core", trans.URL, "URL credential keeps its matched path scope")

	for _, requestURL := range []string{
		"https://example.com:443/v2/dependabot/core-attacker/manifests/latest",
		"https://example.com/v2/dependabot%2Fcore/manifests/latest",
		"https://example.com/v2/dependabot/core/%2e%2e%2fattacker/manifests/latest",
	} {
		req = httptest.NewRequestWithContext(t.Context(), "GET", requestURL, nil)
		proxyCtx = &goproxy.ProxyCtx{}
		_ = handleRequestAndClose(handler, req, proxyCtx)
		assert.Nil(t, proxyCtx.RoundTripper, "URL credential path scope")
	}

	// Different private registry
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://docker.bigco.com/v2/their-repo/manifests/latest", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, proxyCtx)
	rt, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.True(t, ok, "request is assigned a docker registry transport")
	trans = rt.transport.(*registry.BasicTransport)
	assert.Equal(t, bigCoUser, trans.Username, "correct username is set")
	assert.Equal(t, bigCoPassword, trans.Password, "correct password is set")

	// ECR
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://123456789123.dkr.ecr.us-east-2.amazonaws.com", nil)
	req = req.WithContext(context.WithValue(req.Context(), ecrContextKey{}, "ecr-request"))
	proxyCtx = &goproxy.ProxyCtx{}
	req = handleRequestAndClose(handler, req, proxyCtx)
	_, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "ecr request isn't assigned a docker registry transport")
	assertHasBasicAuth(t, req, ecrDockerUser, ecrDockerPassword, "has ecr credentials")
	if assert.NotNil(t, factoryContext, "client factory receives a context") {
		assert.Equal(t, "ecr-request", factoryContext.Value(ecrContextKey{}), "client factory receives request context")
	}
	if assert.NotNil(t, mockECR.requestContext, "ecr request receives a context") {
		assert.Equal(t, "ecr-request", mockECR.requestContext.Value(ecrContextKey{}), "ecr request receives request context")
	}

	// ECR, again
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://123456789123.dkr.ecr.us-east-2.amazonaws.com", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	req = handleRequestAndClose(handler, req, proxyCtx)
	_, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "ecr request isn't assigned a docker registry transport")
	assertHasBasicAuth(t, req, ecrDockerUser, ecrDockerPassword, "has ecr credentials")

	// ECR, mismatch:
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://123456789123.dkr.ecr.us-east-2Xamazonaws.com", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	req = handleRequestAndClose(handler, req, proxyCtx)
	_, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "ecr request isn't assigned a docker registry transport")
	assertUnauthenticated(t, req, "leaked ecr credentials")

	// Missing repo subdomain
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://bigco.com/v2/their-repo/manifests/latest", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, proxyCtx)
	_, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "different subdomain request isn't assigned a docker registry transport")

	// HTTP, not HTTPS
	req = httptest.NewRequestWithContext(t.Context(), "GET", "http://docker.bigco.com/v2/their-repo/manifests/latest", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, proxyCtx)
	_, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "request isn't assigned a docker registry transport")

	// Not a GET request
	req = httptest.NewRequestWithContext(t.Context(), "POST", "https://docker.bigco.com/v2/their-repo/manifests/latest", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, proxyCtx)
	_, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "request isn't assigned a docker registry transport")

	// Nexus, BasicAuth
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://nexus.someco.com/v2/a-repo/manifests/latest", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, proxyCtx)
	rt, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.True(t, ok, "request is assigned a docker registry transport")
	trans = rt.transport.(*registry.BasicTransport)
	assert.Equal(t, hubUser, trans.Username, "correct username is set")
	assert.Equal(t, hubPassword, trans.Password, "correct password is set")
	assert.Equal(t, "https://nexus.someco.com", trans.URL, "correct URL is set")
}

func TestDockerRegistryHandlerProxyOnlyCredentials(t *testing.T) {
	transport := &recordingECRTransport{}
	client := &http.Client{Transport: transport, Timeout: testOIDCClient.Timeout}
	handler := NewDockerRegistryHandler(config.Credentials{
		{
			"type":       "docker_registry",
			"registry":   "ghcr.io",
			"username":   "x-access-token",
			"password":   "automatic-token",
			"proxy-only": true,
		},
		{
			"type":     "docker_registry",
			"registry": "ghcr.io",
			"url":      "https://ghcr.io/dependabot/core",
			"username": "explicit-user",
			"password": "explicit-token",
		},
	}, client, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://ghcr.io/v2/other/image/manifests/latest", nil)
	proxyCtx := &goproxy.ProxyCtx{}
	handleRequestAndClose(handler, req, proxyCtx)
	rt, ok := proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	require.True(t, ok, "automatic credential configures challenge transport")
	trans := rt.transport.(*registry.BasicTransport)
	assert.Equal(t, "x-access-token", trans.Username)
	assert.Equal(t, "automatic-token", trans.Password)

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://ghcr.io/v2/other/image/manifests/latest", nil)
	req.SetBasicAuth(authorizationPlaceholder, "placeholder-password")
	proxyCtx = &goproxy.ProxyCtx{}
	handleRequestAndClose(handler, req, proxyCtx)
	require.NotNil(t, proxyCtx.RoundTripper)
	resp, err := proxyCtx.RoundTripper.RoundTrip(req, proxyCtx)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assertHasBasicAuth(t, req, "x-access-token", "automatic-token", "challenge transport replaces placeholder auth")

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://ghcr.io/v2/other/image/manifests/latest", nil)
	req.SetBasicAuth("caller", "caller-token")
	proxyCtx = &goproxy.ProxyCtx{}
	req = handleRequestAndClose(handler, req, proxyCtx)
	assertHasBasicAuth(t, req, "caller", "caller-token", "automatic credential preserves genuine auth")
	assert.Nil(t, proxyCtx.RoundTripper)

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://ghcr.io/v2/dependabot/core/manifests/latest", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	handleRequestAndClose(handler, req, proxyCtx)
	rt, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	require.True(t, ok, "explicit credential configures challenge transport")
	trans = rt.transport.(*registry.BasicTransport)
	assert.Equal(t, "explicit-user", trans.Username)
	assert.Equal(t, "explicit-token", trans.Password)

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://ghcr.io/v2/dependabot/core-attacker/manifests/latest", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	handleRequestAndClose(handler, req, proxyCtx)
	rt, ok = proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	require.True(t, ok, "sibling path uses host-wide automatic transport")
	trans = rt.transport.(*registry.BasicTransport)
	assert.Equal(t, "x-access-token", trans.Username)

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://ghcr.example/v2/other/image/manifests/latest", nil)
	proxyCtx = &goproxy.ProxyCtx{}
	handleRequestAndClose(handler, req, proxyCtx)
	assert.Nil(t, proxyCtx.RoundTripper, "host mismatch does not configure challenge transport")
}

func TestDockerRegistryHandlerOIDCRepositoryScope(t *testing.T) {
	const tokenURL = "https://token.actions.example.com" //nolint:gosec // test URL
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenURL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder(http.MethodGet, tokenURL,
		httpmock.NewStringResponder(http.StatusOK, `{"count":1,"value":"github-token"}`))
	httpmock.RegisterResponder(
		http.MethodPost,
		"https://login.microsoftonline.com/docker-tenant/oauth2/v2.0/token",
		httpmock.NewStringResponder(
			http.StatusOK,
			`{"access_token":"oidc-token","expires_in":3600,"token_type":"Bearer"}`,
		),
	)

	handler := NewDockerRegistryHandler(config.Credentials{
		{
			"type":       "docker_registry",
			"registry":   "ghcr.io",
			"username":   "x-access-token",
			"password":   "automatic-token",
			"proxy-only": true,
		},
		{
			"type":      "docker_registry",
			"registry":  "ghcr.io",
			"url":       "https://ghcr.io/dependabot/core",
			"tenant-id": "docker-tenant",
			"client-id": "docker-client",
		},
	}, testOIDCClient, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://ghcr.io/v2/dependabot/core/manifests/latest", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "oidc-token", "repository-scoped OIDC credential")

	for _, requestURL := range []string{
		"https://ghcr.io/v2/other/image/blobs/sha256:abc",
		"https://ghcr.io/v2/dependabot/core-attacker/manifests/latest",
	} {
		req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
		proxyCtx := &goproxy.ProxyCtx{}
		handleRequestAndClose(handler, req, proxyCtx)
		rt, ok := proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
		require.True(t, ok, "other repositories use host-wide fallback")
		transport := rt.transport.(*registry.BasicTransport)
		assert.Equal(t, "x-access-token", transport.Username)
		assert.Equal(t, "automatic-token", transport.Password)
	}
}

func TestDockerRegistryHandlerURLCredentialUsesMatchedRequestOrigin(t *testing.T) {
	client := &http.Client{Transport: &recordingECRTransport{}, Timeout: testOIDCClient.Timeout}
	handler := NewDockerRegistryHandler(config.Credentials{
		{
			"type":     "docker_registry",
			"url":      "https://example.com/dependabot/core/",
			"username": "user",
			"password": "password",
		},
	}, client, nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://EXAMPLE.com:443/v2/dependabot/core/blobs/sha256:abc", nil)
	proxyCtx := &goproxy.ProxyCtx{}
	handleRequestAndClose(handler, req, proxyCtx)

	rt, ok := proxyCtx.RoundTripper.(*dockerRegistryRoundTripper)
	require.True(t, ok)
	transport := rt.transport.(*registry.BasicTransport)
	assert.Equal(t, "https://EXAMPLE.com:443/v2/dependabot/core", transport.URL)

	resp, err := proxyCtx.RoundTripper.RoundTrip(req, proxyCtx)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assertHasBasicAuth(t, req, "user", "password", "transport authenticates the matched request form")
}

func TestDockerRegistryHandlerRejectsConflictingCredentialLocations(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		url      string
		request  string
	}{
		{
			name:     "different origins",
			registry: "ghcr.io",
			url:      "https://attacker.example.com/dependabot/core",
			request:  "https://ghcr.io/v2/other/image/manifests/latest",
		},
		{
			name:     "sibling paths",
			registry: "https://ghcr.io/team-a",
			url:      "https://ghcr.io/team-b/core",
			request:  "https://ghcr.io/v2/team-a/manifests/latest",
		},
		{
			name:     "invalid URL",
			registry: "ghcr.io",
			url:      "https://ghcr.io/%zz",
			request:  "https://ghcr.io/v2/other/image/manifests/latest",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := NewDockerRegistryHandler(config.Credentials{
				{
					"type":     "docker_registry",
					"registry": test.registry,
					"url":      test.url,
					"username": "user",
					"password": "password",
				},
			}, testOIDCClient, nil)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, test.request, nil)
			proxyCtx := &goproxy.ProxyCtx{}
			handleRequestAndClose(handler, req, proxyCtx)

			assert.Nil(t, proxyCtx.RoundTripper, "conflicting credential is skipped")
			assertUnauthenticated(t, req, "conflicting credential is skipped")
		})
	}
}

//nolint:gosec // The test credentials are intentionally fake fixtures.
func TestDefaultGetECRClientUsesInjectedHTTPClient(t *testing.T) {
	transport := &recordingECRTransport{}
	client := &http.Client{Transport: transport, Timeout: testOIDCClient.Timeout}

	ecrClient, err := defaultGetECRClient(t.Context(), "us-east-2", "access-key", "secret-key", client)
	require.NoError(t, err)
	_, err = ecrClient.GetAuthorizationToken(t.Context(), &ecr.GetAuthorizationTokenInput{})
	require.NoError(t, err)

	require.NotNil(t, transport.request)
	assert.Equal(t, http.MethodPost, transport.request.Method)
	assert.Equal(t, "api.ecr.us-east-2.amazonaws.com", transport.request.URL.Host)
}

type recordingECRTransport struct {
	request *http.Request
}

func (t *recordingECRTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.request = req
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"authorizationData":[]}`)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

type mockECRClient struct {
	user           string
	token          string
	requestContext context.Context
}

func (c *mockECRClient) GetAuthorizationToken(
	ctx context.Context,
	_ *ecr.GetAuthorizationTokenInput,
	_ ...func(*ecr.Options),
) (*ecr.GetAuthorizationTokenOutput, error) {
	c.requestContext = ctx
	authToken := base64.StdEncoding.EncodeToString([]byte(c.user + ":" + c.token))
	return &ecr.GetAuthorizationTokenOutput{
		AuthorizationData: []types.AuthorizationData{
			{
				AuthorizationToken: new(authToken),
			},
		},
	}, nil
}
