package handlers

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/config"
)

type oidcHandler interface {
	HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response)
}

type mockHttpRequest struct {
	verb     string
	url      string
	response string
}

func TestOIDCURLsAreAuthenticated(t *testing.T) {
	testTenantId := "12345678-1234-1234-1234-123456789012"
	testClientId := "87654321-4321-4321-4321-210987654321"
	testRegion := "us-east-1"
	testCases := []struct {
		name               string
		provider           string
		handlerFactory     func(creds config.Credentials) oidcHandler
		credentials        config.Credentials
		urlMocks           []mockHttpRequest
		expectedLogLines   []string
		urlsToAuthenticate []string
	}{
		//
		// Cargo
		//
		{
			name:     "Cargo",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewCargoRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "cargo_registry",
					"url":          "https://cargo.example.com/packages",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for cargo registry: https://cargo.example.com/packages",
			},
			urlsToAuthenticate: []string{
				"https://cargo.example.com/packages/some-package",
			},
		},
		{
			name:     "Cargo",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewCargoRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "cargo_registry",
					"url":       "https://cargo.example.com/packages",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for cargo registry: https://cargo.example.com/packages",
			},
			urlsToAuthenticate: []string{
				"https://cargo.example.com/packages/some-package",
			},
		},
		{
			name:     "Cargo",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewCargoRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "cargo_registry",
					"url":                      "https://jfrog.example.com/packages",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for cargo registry: https://jfrog.example.com/packages",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/packages/some-package",
			},
		},
		//
		// Composer
		//
		{
			name:     "Composer",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewComposerHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "composer_repository",
					"registry":     "https://composer.example.com",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for composer repository: composer.example.com",
			},
			urlsToAuthenticate: []string{
				"https://composer.example.com/some-package",
			},
		},
		{
			name:     "Composer",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewComposerHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "composer_repository",
					"registry":  "https://composer.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for composer repository: composer.example.com",
			},
			urlsToAuthenticate: []string{
				"https://composer.example.com/some-package",
			},
		},
		{
			name:     "Composer",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewComposerHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "composer_repository",
					"registry":                 "https://jfrog.example.com",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for composer repository: jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		//
		// Docker
		//
		{
			name:     "Docker",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewDockerRegistryHandler(creds, &http.Transport{}, nil)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "docker_registry",
					"registry":     "https://docker.example.com",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for docker registry: https://docker.example.com",
			},
			urlsToAuthenticate: []string{
				"https://docker.example.com/some-package",
			},
		},
		{
			name:     "Docker",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewDockerRegistryHandler(creds, &http.Transport{}, nil)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "docker_registry",
					"registry":  "https://docker.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for docker registry: https://docker.example.com",
			},
			urlsToAuthenticate: []string{
				"https://docker.example.com/some-package",
			},
		},
		{
			name:     "Docker with URL",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewDockerRegistryHandler(creds, &http.Transport{}, nil)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "docker_registry",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for docker registry: jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		//
		// Go proxy
		//
		{
			name:     "Go proxy",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewGoProxyServerHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "goproxy_server",
					"url":          "https://goproxy.example.com",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for goproxy server: https://goproxy.example.com",
			},
			urlsToAuthenticate: []string{
				"https://goproxy.example.com/packages/some-package",
			},
		},
		{
			name:     "Go proxy with host",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewGoProxyServerHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "goproxy_server",
					"host":      "goproxy.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for goproxy server: goproxy.example.com",
			},
			urlsToAuthenticate: []string{
				"https://goproxy.example.com/packages/some-package",
			},
		},
		{
			name:     "Go proxy",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewGoProxyServerHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "goproxy_server",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for goproxy server: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/packages/some-package",
			},
		},
		//
		// Helm
		//
		{
			name:     "Helm registry",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHelmRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "helm_registry",
					"registry":     "https://helm.example.com",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for helm registry: https://helm.example.com",
			},
			urlsToAuthenticate: []string{
				"https://helm.example.com/some-package",
			},
		},
		{
			name:     "Helm registry",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHelmRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "helm_registry",
					"registry":  "https://helm.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for helm registry: https://helm.example.com",
			},
			urlsToAuthenticate: []string{
				"https://helm.example.com/some-package",
			},
		},
		{
			name:     "Helm registry with url",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHelmRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "helm_registry",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for helm registry: jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		//
		// Hex
		//
		{
			name:     "Hex",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHexRepositoryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "hex_repository",
					"url":          "https://hex.example.com",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for hex repository: https://hex.example.com",
			},
			urlsToAuthenticate: []string{
				"https://hex.example.com/some-package",
			},
		},
		{
			name:     "Hex",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHexRepositoryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "hex_repository",
					"url":       "https://hex.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for hex repository: https://hex.example.com",
			},
			urlsToAuthenticate: []string{
				"https://hex.example.com/some-package",
			},
		},
		{
			name:     "Hex",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHexRepositoryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "hex_repository",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for hex repository: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		//
		// Maven
		//
		{
			name:     "Maven",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewMavenRepositoryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "maven_repository",
					"url":          "https://maven.example.com/packages",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for maven repository: maven.example.com",
			},
			urlsToAuthenticate: []string{
				"https://maven.example.com/packages/some-package",
			},
		},
		{
			name:     "Maven",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewMavenRepositoryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "maven_repository",
					"url":       "https://maven.example.com/packages",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for maven repository: maven.example.com",
			},
			urlsToAuthenticate: []string{
				"https://maven.example.com/packages/some-package",
			},
		},
		{
			name:     "Maven",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewMavenRepositoryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "maven_repository",
					"url":                      "https://jfrog.example.com/packages",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for maven repository: jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/packages/some-package",
			},
		},
		//
		// NPM
		//
		{
			name:     "NPM",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNPMRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "npm_registry",
					"url":          "https://npm.example.com",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for npm registry: npm.example.com",
			},
			urlsToAuthenticate: []string{
				"https://npm.example.com/some-package",
			},
		},
		{
			name:     "NPM",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNPMRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "npm_registry",
					"url":       "https://npm.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for npm registry: npm.example.com",
			},
			urlsToAuthenticate: []string{
				"https://npm.example.com/some-package",
			},
		},
		{
			name:     "NPM",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNPMRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "npm_registry",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for npm registry: jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		//
		// NuGet
		//
		{
			name:     "NuGet",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNugetFeedHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "nuget_feed",
					"url":          "https://nuget.example.com/index.json",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{
				{
					verb:     "GET",
					url:      "https://nuget.example.com/index.json",
					response: `{"version":"3.0.0","resources":[{"@id":"https://nuget.example.com/v3/packages","@type":"PackageBaseAddress/3.0.0"}]}`,
				},
			},
			expectedLogLines: []string{
				"registered aws OIDC credentials for nuget feed: https://nuget.example.com/index.json",
				"  registered aws OIDC credentials for nuget resource: https://nuget.example.com/v3/packages",
			},
			urlsToAuthenticate: []string{
				"https://nuget.example.com/index.json",                          // base url
				"https://nuget.example.com/v3/packages/some.package/index.json", // package url
			},
		},
		{
			name:     "NuGet",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNugetFeedHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "nuget_feed",
					"url":       "https://nuget.example.com/index.json",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{
				{
					verb:     "GET",
					url:      "https://nuget.example.com/index.json",
					response: `{"version":"3.0.0","resources":[{"@id":"https://nuget.example.com/v3/packages","@type":"PackageBaseAddress/3.0.0"}]}`,
				},
			},
			expectedLogLines: []string{
				"registered azure OIDC credentials for nuget feed: https://nuget.example.com/index.json",
				"  registered azure OIDC credentials for nuget resource: https://nuget.example.com/v3/packages",
			},
			urlsToAuthenticate: []string{
				"https://nuget.example.com/index.json",                          // base url
				"https://nuget.example.com/v3/packages/some.package/index.json", // package url
			},
		},
		{
			name:     "NuGet",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNugetFeedHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "nuget_feed",
					"url":                      "https://jfrog.example.com/index.json",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{
				{
					verb:     "GET",
					url:      "https://jfrog.example.com/index.json",
					response: `{"version":"3.0.0","resources":[{"@id":"https://jfrog.example.com/v3/packages","@type":"PackageBaseAddress/3.0.0"}]}`,
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for nuget feed: https://jfrog.example.com/index.json",
				"  registered jfrog OIDC credentials for nuget resource: https://jfrog.example.com/v3/packages",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/index.json",                          // base url
				"https://jfrog.example.com/v3/packages/some.package/index.json", // package url
			},
		},
		//
		// Pub
		//
		{
			name:     "Pub",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPubRepositoryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "pub_repository",
					"url":          "https://pub.example.com",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for pub repository: https://pub.example.com",
			},
			urlsToAuthenticate: []string{
				"https://pub.example.com/some-package",
			},
		},
		{
			name:     "Pub",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPubRepositoryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "pub_repository",
					"url":       "https://pub.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for pub repository: https://pub.example.com",
			},
			urlsToAuthenticate: []string{
				"https://pub.example.com/some-package",
			},
		},
		{
			name:     "Pub",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPubRepositoryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "pub_repository",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for pub repository: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		//
		// Python
		//
		{
			name:     "Python",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPythonIndexHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "python_index",
					"url":          "https://python.example.com",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for python index: python.example.com",
			},
			urlsToAuthenticate: []string{
				"https://python.example.com/some-package",
			},
		},
		{
			name:     "Python",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPythonIndexHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "python_index",
					"url":       "https://python.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for python index: python.example.com",
			},
			urlsToAuthenticate: []string{
				"https://python.example.com/some-package",
			},
		},
		{
			name:     "Python",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPythonIndexHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "python_index",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for python index: jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		//
		// RubyGems
		//
		{
			name:     "RubyGems",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewRubyGemsServerHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "rubygems_server",
					"host":         "https://rubygems.example.com",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for rubygems server: https://rubygems.example.com",
			},
			urlsToAuthenticate: []string{
				"https://rubygems.example.com/some-package",
			},
		},
		{
			name:     "RubyGems",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewRubyGemsServerHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "rubygems_server",
					"host":      "https://rubygems.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for rubygems server: https://rubygems.example.com",
			},
			urlsToAuthenticate: []string{
				"https://rubygems.example.com/some-package",
			},
		},
		{
			name:     "RubyGems",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewRubyGemsServerHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "rubygems_server",
					"url":                      "https://jfrog.example.com",
					"host":                     "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for rubygems server: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		//
		// Terraform
		//
		{
			name:     "Terraform",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewTerraformRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "terraform_registry",
					"url":          "https://terraform.example.com",
					"aws-region":   testRegion,
					"account-id":   "123456789012",
					"role-name":    "MyRole",
					"domain":       "my-domain",
					"domain-owner": "9876543210",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered aws OIDC credentials for terraform registry: terraform.example.com",
			},
			urlsToAuthenticate: []string{
				"https://terraform.example.com/some-package",
			},
		},
		{
			name:     "Terraform with host",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewTerraformRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "terraform_registry",
					"host":      "https://terraform.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered azure OIDC credentials for terraform registry: https://terraform.example.com",
			},
			urlsToAuthenticate: []string{
				"https://terraform.example.com/some-package",
			},
		},
		{
			name:     "Terraform",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewTerraformRegistryHandler(creds)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "terraform_registry",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			urlMocks: []mockHttpRequest{},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for terraform registry: jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s - %s", tc.name, tc.provider), func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

			// mock URLs
			for _, mockReq := range tc.urlMocks {
				httpmock.RegisterResponder(mockReq.verb, mockReq.url,
					httpmock.NewStringResponder(200, mockReq.response))
			}

			// mock GitHub OIDC token request
			tokenUrl := "https://token.actions.example.com" //nolint:gosec // test URL
			httpmock.RegisterResponder("GET", tokenUrl,
				httpmock.NewStringResponder(200, `{
				"count": 1,
				"value": "sometoken"
			}`))

			// mock provider URLs
			switch tc.provider {
			case "aws":
				// mock AWS OIDC token request
				httpmock.RegisterResponder("POST", "https://sts.amazonaws.com",
					httpmock.NewStringResponder(200, `<?xml version="1.0" encoding="UTF-8"?>
					<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
					  <AssumeRoleWithWebIdentityResult>
					    <Credentials>
					      <AccessKeyId>ASIA_TEST_ACCESS_KEY</AccessKeyId>
					      <SecretAccessKey>TEST_SECRET_ACCESS_KEY</SecretAccessKey>
					      <SessionToken>TEST_SESSION_TOKEN</SessionToken>
					      <Expiration>2024-12-31T23:59:59Z</Expiration>
					    </Credentials>
					  </AssumeRoleWithWebIdentityResult>
					</AssumeRoleWithWebIdentityResponse>`))
				httpmock.RegisterResponder("POST", "https://codeartifact."+testRegion+".amazonaws.com/v1/authorization-token",
					httpmock.NewStringResponder(200, `{
					  "authorizationToken": "__test_token__",
					  "expiration": 1E5
					}`))
			case "azure":
				// mock Azure OIDC token request
				httpmock.RegisterResponder("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", testTenantId), httpmock.NewStringResponder(200, `{
					"access_token": "__test_token__",
					"expires_in": 3600,
					"token_type": "Bearer"
				}`))
			case "jfrog":
				// mock JFrog OIDC token request
				httpmock.RegisterResponder("POST", "https://jfrog.example.com/access/api/v1/oidc/token", httpmock.NewStringResponder(200, `{
					"access_token": "__test_token__",
					"expires_in": 3600
				}`))
			default:
				t.Fatal("unsupported provider in test case: " + tc.provider)
			}

			// ensure OIDC auth is enabled
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenUrl)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "sometoken")

			// create handler and capture log output
			var buf bytes.Buffer
			log.SetOutput(&buf)
			handler := tc.handlerFactory(tc.credentials)
			logContents := buf.String()

			// check expected log lines
			for _, expectedLine := range tc.expectedLogLines {
				assert.True(t, strings.Contains(logContents, expectedLine), "include log line: "+expectedLine)
			}

			// check URLs are authenticated
			for _, urlToAuth := range tc.urlsToAuthenticate {
				req := httptest.NewRequest("GET", urlToAuth, nil)
				req, _ = handler.HandleRequest(req, nil)
				assertHasTokenAuth(t, req, "Bearer", "__test_token__", "package url: "+urlToAuth)
			}
		})
	}
}
