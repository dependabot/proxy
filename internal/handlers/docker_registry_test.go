package handlers

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/elazarl/goproxy"
	"github.com/stackrox/docker-registry-client/registry"
	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/config"
)

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
			"url":      "https://example.com:443/reg-path",
			"username": hubUser,
			"password": hubPassword,
		},
	}
	getECRClient := func(region, keyID, secretKey string) (ECRClient, error) {
		return &mockECRClient{user: ecrDockerUser, token: ecrDockerPassword}, nil
	}
	handler := NewDockerRegistryHandler(credentials, &http.Transport{}, getECRClient)

	// Regular private registry
	req := httptest.NewRequest("GET", "https://registry.hub.docker.com/my-repo", nil)
	ctx := &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, ctx)
	rt, ok := ctx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.True(t, ok, "request is assigned a docker registry transport")
	trans := rt.transport.(*registry.BasicTransport)
	assert.Equal(t, hubUser, trans.Username, "correct username is set")
	assert.Equal(t, hubPassword, trans.Password, "correct password is set")

	// Registry using URL not registry key
	req = httptest.NewRequest("GET", "https://registry.hub.docker.com/my-repo", nil)
	ctx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, ctx)
	rt, ok = ctx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.True(t, ok, "request is assigned a docker registry transport")
	trans = rt.transport.(*registry.BasicTransport)
	assert.Equal(t, hubUser, trans.Username, "correct username is set")
	assert.Equal(t, hubPassword, trans.Password, "correct password is set")

	// Different private registry
	req = httptest.NewRequest("GET", "https://docker.bigco.com/their-repo", nil)
	ctx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, ctx)
	rt, ok = ctx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.True(t, ok, "request is assigned a docker registry transport")
	trans = rt.transport.(*registry.BasicTransport)
	assert.Equal(t, bigCoUser, trans.Username, "correct username is set")
	assert.Equal(t, bigCoPassword, trans.Password, "correct password is set")

	// ECR
	req = httptest.NewRequest("GET", "https://123456789123.dkr.ecr.us-east-2.amazonaws.com", nil)
	ctx = &goproxy.ProxyCtx{}
	req = handleRequestAndClose(handler, req, ctx)
	_, ok = ctx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "ecr request isn't assigned a docker registry transport")
	assertHasBasicAuth(t, req, ecrDockerUser, ecrDockerPassword, "has ecr credentials")

	// ECR, again
	req = httptest.NewRequest("GET", "https://123456789123.dkr.ecr.us-east-2.amazonaws.com", nil)
	ctx = &goproxy.ProxyCtx{}
	req = handleRequestAndClose(handler, req, ctx)
	_, ok = ctx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "ecr request isn't assigned a docker registry transport")
	assertHasBasicAuth(t, req, ecrDockerUser, ecrDockerPassword, "has ecr credentials")

	// ECR, mismatch:
	req = httptest.NewRequest("GET", "https://123456789123.dkr.ecr.us-east-2Xamazonaws.com", nil)
	ctx = &goproxy.ProxyCtx{}
	req = handleRequestAndClose(handler, req, ctx)
	_, ok = ctx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "ecr request isn't assigned a docker registry transport")
	assertUnauthenticated(t, req, "leaked ecr credentials")

	// Missing repo subdomain
	req = httptest.NewRequest("GET", "https://bigco.com/their-repo", nil)
	ctx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, ctx)
	_, ok = ctx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "different subdomain request isn't assigned a docker registry transport")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://docker.bigco.com/their-repo", nil)
	ctx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, ctx)
	_, ok = ctx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "request isn't assigned a docker registry transport")

	// Not a GET request
	req = httptest.NewRequest("POST", "https://docker.bigco.com/their-repo", nil)
	ctx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, ctx)
	_, ok = ctx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.False(t, ok, "request isn't assigned a docker registry transport")

	// Nexus, BasicAuth
	req = httptest.NewRequest("GET", "https://nexus.someco.com/a-repo", nil)
	ctx = &goproxy.ProxyCtx{}
	_ = handleRequestAndClose(handler, req, ctx)
	rt, ok = ctx.RoundTripper.(*dockerRegistryRoundTripper)
	assert.True(t, ok, "request is assigned a docker registry transport")
	trans = rt.transport.(*registry.BasicTransport)
	assert.Equal(t, hubUser, trans.Username, "correct username is set")
	assert.Equal(t, hubPassword, trans.Password, "correct password is set")
	assert.Equal(t, "https://nexus.someco.com", trans.URL, "correct URL is set")
}

type mockECRClient struct {
	user  string
	token string
}

func (c *mockECRClient) GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	authToken := base64.StdEncoding.EncodeToString([]byte(c.user + ":" + c.token))
	return &ecr.GetAuthorizationTokenOutput{
		AuthorizationData: []types.AuthorizationData{
			{
				AuthorizationToken: aws.String(authToken),
			},
		},
	}, nil
}
