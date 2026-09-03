package handlers

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/testhelpers"
)

type oidcHandler interface {
	HandleRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response)
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
		serviceIndexURL    string
		resourceURL        string
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
				return NewCargoRegistryHandler(creds, testOIDCClient)
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
				return NewCargoRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "cargo_registry",
					"url":       "https://cargo.example.com/packages",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
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
				return NewCargoRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "cargo_registry",
					"url":                      "https://jfrog.example.com/packages",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for cargo registry: https://jfrog.example.com/packages",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/packages/some-package",
			},
		},
		{
			name:     "Cargo",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewCargoRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "cargo_registry",
					"url":          "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for cargo registry: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "Cargo",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewCargoRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "cargo_registry",
					"url":                        "https://us-central1-cargo.pkg.dev/my-project/my-repo",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for cargo registry: https://us-central1-cargo.pkg.dev/my-project/my-repo",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-cargo.pkg.dev/my-project/my-repo/some-package",
			},
		},
		//
		// Composer
		//
		{
			name:     "Composer",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewComposerHandler(creds, testOIDCClient)
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
			expectedLogLines: []string{
				"registered aws OIDC credentials for composer repository: https://composer.example.com",
			},
			urlsToAuthenticate: []string{
				"https://composer.example.com/some-package",
			},
		},
		{
			name:     "Composer",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewComposerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "composer_repository",
					"registry":  "https://composer.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			expectedLogLines: []string{
				"registered azure OIDC credentials for composer repository: https://composer.example.com",
			},
			urlsToAuthenticate: []string{
				"https://composer.example.com/some-package",
			},
		},
		{
			name:     "Composer",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewComposerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "composer_repository",
					"registry":                 "https://jfrog.example.com",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for composer repository: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		{
			name:     "Composer",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewComposerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "composer_repository",
					"registry":     "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for composer repository: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "Composer",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewComposerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "composer_repository",
					"registry":                   "https://us-central1-composer.pkg.dev/my-project/my-repo",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for composer repository: https://us-central1-composer.pkg.dev/my-project/my-repo",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-composer.pkg.dev/my-project/my-repo/some-package",
			},
		},

		//
		// Docker
		//
		{
			name:     "Docker",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewDockerRegistryHandler(creds, testOIDCClient, nil)
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
			expectedLogLines: []string{
				"registered aws OIDC credentials for docker registry: https://docker.example.com",
			},
			urlsToAuthenticate: []string{
				"https://docker.example.com/v2/some-package/manifests/latest",
			},
		},
		{
			name:     "Docker",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewDockerRegistryHandler(creds, testOIDCClient, nil)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "docker_registry",
					"registry":  "https://docker.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			expectedLogLines: []string{
				"registered azure OIDC credentials for docker registry: https://docker.example.com",
			},
			urlsToAuthenticate: []string{
				"https://docker.example.com/v2/some-package/manifests/latest",
			},
		},
		{
			name:     "Docker with URL",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewDockerRegistryHandler(creds, testOIDCClient, nil)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "docker_registry",
					"url":                      "https://jfrog.example.com/dependabot",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for docker registry: https://jfrog.example.com/v2/dependabot",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/v2/dependabot/manifests/latest",
			},
		},
		{
			name:     "Docker",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewDockerRegistryHandler(creds, testOIDCClient, nil)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "docker_registry",
					"registry":     "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for docker registry: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/v2/some-package/manifests/latest",
			},
		},
		{
			name:     "Docker",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewDockerRegistryHandler(creds, testOIDCClient, nil)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "docker_registry",
					"registry":                   "https://us-central1-docker.pkg.dev",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for docker registry: https://us-central1-docker.pkg.dev",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-docker.pkg.dev/v2/some-package/manifests/latest",
			},
		},
		//
		// Go proxy
		//
		{
			name:     "Go proxy",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewGoProxyServerHandler(creds, testOIDCClient)
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
				return NewGoProxyServerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "goproxy_server",
					"host":      "goproxy.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
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
				return NewGoProxyServerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "goproxy_server",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for goproxy server: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/packages/some-package",
			},
		},
		{
			name:     "Go proxy",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewGoProxyServerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "goproxy_server",
					"url":          "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for goproxy server: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "Go proxy",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewGoProxyServerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "goproxy_server",
					"url":                        "https://us-central1-go.pkg.dev/my-project/my-repo",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for goproxy server: https://us-central1-go.pkg.dev/my-project/my-repo",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-go.pkg.dev/my-project/my-repo/some-package",
			},
		},
		//
		// Helm
		//
		{
			name:     "Helm registry",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHelmRegistryHandler(creds, testOIDCClient)
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
				return NewHelmRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "helm_registry",
					"registry":  "https://helm.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
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
				return NewHelmRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "helm_registry",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for helm registry: jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		{
			name:     "Helm registry",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHelmRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "helm_registry",
					"registry":     "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for helm registry: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "Helm registry",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHelmRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "helm_registry",
					"registry":                   "https://us-central1-helm.pkg.dev/my-project/my-repo",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for helm registry: https://us-central1-helm.pkg.dev/my-project/my-repo",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-helm.pkg.dev/my-project/my-repo/some-package",
			},
		},
		//
		// Hex
		//
		{
			name:     "Hex",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHexRepositoryHandler(creds, testOIDCClient)
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
				return NewHexRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "hex_repository",
					"url":       "https://hex.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
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
				return NewHexRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "hex_repository",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for hex repository: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		{
			name:     "Hex",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHexRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "hex_repository",
					"url":          "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for hex repository: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "Hex",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewHexRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "hex_repository",
					"url":                        "https://us-central1-hex.pkg.dev/my-project/my-repo",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for hex repository: https://us-central1-hex.pkg.dev/my-project/my-repo",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-hex.pkg.dev/my-project/my-repo/some-package",
			},
		},
		//
		// Maven
		//
		{
			name:     "Maven",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewMavenRepositoryHandler(creds, testOIDCClient)
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
			expectedLogLines: []string{
				"registered aws OIDC credentials for maven repository: https://maven.example.com/packages",
			},
			urlsToAuthenticate: []string{
				"https://maven.example.com/packages/some-package",
			},
		},
		{
			name:     "Maven",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewMavenRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "maven_repository",
					"url":       "https://maven.example.com/packages",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			expectedLogLines: []string{
				"registered azure OIDC credentials for maven repository: https://maven.example.com/packages",
			},
			urlsToAuthenticate: []string{
				"https://maven.example.com/packages/some-package",
			},
		},
		{
			name:     "Maven",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewMavenRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "maven_repository",
					"url":                      "https://jfrog.example.com/packages",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for maven repository: https://jfrog.example.com/packages",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/packages/some-package",
			},
		},
		{
			name:     "Maven",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewMavenRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "maven_repository",
					"url":          "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for maven repository: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "Maven",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewMavenRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "maven_repository",
					"url":                        "https://us-central1-maven.pkg.dev/my-project/my-repo",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for maven repository: https://us-central1-maven.pkg.dev/my-project/my-repo",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-maven.pkg.dev/my-project/my-repo/some-package",
			},
		},
		//
		// NPM
		//
		{
			name:     "NPM",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNPMRegistryHandler(creds, testOIDCClient)
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
			expectedLogLines: []string{
				"registered aws OIDC credentials for npm registry: https://npm.example.com",
			},
			urlsToAuthenticate: []string{
				"https://npm.example.com/some-package",
			},
		},
		{
			name:     "NPM",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNPMRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "npm_registry",
					"url":       "https://npm.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			expectedLogLines: []string{
				"registered azure OIDC credentials for npm registry: https://npm.example.com",
			},
			urlsToAuthenticate: []string{
				"https://npm.example.com/some-package",
			},
		},
		{
			name:     "NPM",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNPMRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "npm_registry",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for npm registry: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		{
			name:     "NPM",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNPMRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "npm_registry",
					"url":          "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for npm registry: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "NPM",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNPMRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "npm_registry",
					"url":                        "https://us-central1-npm.pkg.dev/my-project/my-repo",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for npm registry: https://us-central1-npm.pkg.dev/my-project/my-repo",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-npm.pkg.dev/my-project/my-repo/some-package",
			},
		},
		//
		// NuGet
		//
		{
			name:     "NuGet",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNugetFeedHandler(creds, testOIDCClient)
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
			serviceIndexURL: "https://nuget.example.com/index.json",
			resourceURL:     "https://nuget.example.com/v3/packages",
			expectedLogLines: []string{
				"registered aws OIDC credentials for nuget feed: https://nuget.example.com/index.json",
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
				return NewNugetFeedHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "nuget_feed",
					"url":       "https://nuget.example.com/index.json",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			serviceIndexURL: "https://nuget.example.com/index.json",
			resourceURL:     "https://nuget.example.com/v3/packages",
			expectedLogLines: []string{
				"registered azure OIDC credentials for nuget feed: https://nuget.example.com/index.json",
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
				return NewNugetFeedHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "nuget_feed",
					"url":                      "https://jfrog.example.com/index.json",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			serviceIndexURL: "https://jfrog.example.com/index.json",
			resourceURL:     "https://jfrog.example.com/v3/packages",
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for nuget feed: https://jfrog.example.com/index.json",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/index.json",                          // base url
				"https://jfrog.example.com/v3/packages/some.package/index.json", // package url
			},
		},
		{
			name:     "NuGet",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNugetFeedHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "nuget_feed",
					"url":          "https://cloudsmith.example.com/v3/index.json",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			serviceIndexURL: "https://cloudsmith.example.com/v3/index.json",
			resourceURL:     "https://cloudsmith.example.com/v3/packages",
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for nuget feed: https://cloudsmith.example.com/v3/index.json",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/v3/index.json",                       // base url
				"https://cloudsmith.example.com/v3/packages/some.package/index.json", // package url
			},
		},
		{
			name:     "NuGet",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewNugetFeedHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "nuget_feed",
					"url":                        "https://us-central1-nuget.pkg.dev/my-project/my-repo/index.json",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			serviceIndexURL: "https://us-central1-nuget.pkg.dev/my-project/my-repo/index.json",
			resourceURL:     "https://us-central1-nuget.pkg.dev/my-project/my-repo/v3/packages",
			expectedLogLines: []string{
				"registered gcp OIDC credentials for nuget feed: https://us-central1-nuget.pkg.dev/my-project/my-repo/index.json",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-nuget.pkg.dev/my-project/my-repo/index.json",                          // base url
				"https://us-central1-nuget.pkg.dev/my-project/my-repo/v3/packages/some.package/index.json", // package url
			},
		},
		//
		// Pub
		//
		{
			name:     "Pub",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPubRepositoryHandler(creds, testOIDCClient)
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
				return NewPubRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "pub_repository",
					"url":       "https://pub.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
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
				return NewPubRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "pub_repository",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for pub repository: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		{
			name:     "Pub",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPubRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "pub_repository",
					"url":          "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for pub repository: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "Pub",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPubRepositoryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "pub_repository",
					"url":                        "https://us-central1-pub.pkg.dev/my-project/my-repo",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for pub repository: https://us-central1-pub.pkg.dev/my-project/my-repo",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-pub.pkg.dev/my-project/my-repo/some-package",
			},
		},
		//
		// Python
		//
		{
			name:     "Python",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPythonIndexHandler(creds, testOIDCClient)
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
			expectedLogLines: []string{
				"registered aws OIDC credentials for python index: https://python.example.com",
			},
			urlsToAuthenticate: []string{
				"https://python.example.com/some-package",
			},
		},
		{
			name:     "Python",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPythonIndexHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "python_index",
					"url":       "https://python.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
			expectedLogLines: []string{
				"registered azure OIDC credentials for python index: https://python.example.com",
			},
			urlsToAuthenticate: []string{
				"https://python.example.com/some-package",
			},
		},
		{
			name:     "Python",
			provider: "jfrog",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPythonIndexHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "python_index",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for python index: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		{
			name:     "Python",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPythonIndexHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "python_index",
					"url":          "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for python index: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "Python",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewPythonIndexHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "python_index",
					"index-url":                  "https://us-central1-python.pkg.dev/my-project/my-repo/simple",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for python index: https://us-central1-python.pkg.dev/my-project/my-repo/",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-python.pkg.dev/my-project/my-repo/simple/some-package",
			},
		},
		//
		// RubyGems
		//
		{
			name:     "RubyGems",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewRubyGemsServerHandler(creds, testOIDCClient)
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
				return NewRubyGemsServerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "rubygems_server",
					"host":      "https://rubygems.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
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
				return NewRubyGemsServerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "rubygems_server",
					"url":                      "https://jfrog.example.com",
					"host":                     "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for rubygems server: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		{
			name:     "RubyGems",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewRubyGemsServerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "rubygems_server",
					"url":          "https://cloudsmith.example.com",
					"host":         "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for rubygems server: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "RubyGems",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewRubyGemsServerHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "rubygems_server",
					"url":                        "https://us-central1-ruby.pkg.dev/my-project/my-repo",
					"host":                       "https://us-central1-ruby.pkg.dev/my-project/my-repo",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for rubygems server: https://us-central1-ruby.pkg.dev/my-project/my-repo",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-ruby.pkg.dev/my-project/my-repo/some-package",
			},
		},
		//
		// Terraform
		//
		{
			name:     "Terraform",
			provider: "aws",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewTerraformRegistryHandler(creds, testOIDCClient)
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
			expectedLogLines: []string{
				"registered aws OIDC credentials for terraform registry: https://terraform.example.com",
			},
			urlsToAuthenticate: []string{
				"https://terraform.example.com/some-package",
			},
		},
		{
			name:     "Terraform with host",
			provider: "azure",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewTerraformRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":      "terraform_registry",
					"host":      "https://terraform.example.com",
					"tenant-id": testTenantId,
					"client-id": testClientId,
				},
			},
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
				return NewTerraformRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                     "terraform_registry",
					"url":                      "https://jfrog.example.com",
					"jfrog-oidc-provider-name": "proxy-test",
				},
			},
			expectedLogLines: []string{
				"registered jfrog OIDC credentials for terraform registry: https://jfrog.example.com",
			},
			urlsToAuthenticate: []string{
				"https://jfrog.example.com/some-package",
			},
		},
		{
			name:     "Terraform",
			provider: "cloudsmith",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewTerraformRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":         "terraform_registry",
					"url":          "https://cloudsmith.example.com",
					"namespace":    "space",
					"service-slug": "repo",
					"audience":     "my-audience",
				},
			},
			expectedLogLines: []string{
				"registered cloudsmith OIDC credentials for terraform registry: https://cloudsmith.example.com",
			},
			urlsToAuthenticate: []string{
				"https://cloudsmith.example.com/some-package",
			},
		},
		{
			name:     "Terraform",
			provider: "gcp",
			handlerFactory: func(creds config.Credentials) oidcHandler {
				return NewTerraformRegistryHandler(creds, testOIDCClient)
			},
			credentials: config.Credentials{
				config.Credential{
					"type":                       "terraform_registry",
					"url":                        "https://us-central1-terraform.pkg.dev/my-project/my-repo",
					"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
				},
			},
			expectedLogLines: []string{
				"registered gcp OIDC credentials for terraform registry: https://us-central1-terraform.pkg.dev/my-project/my-repo",
			},
			urlsToAuthenticate: []string{
				"https://us-central1-terraform.pkg.dev/my-project/my-repo/some-package",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s - %s", tc.name, tc.provider), func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

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
			case "cloudsmith":
				namespace := tc.credentials[0]["namespace"]
				httpmock.RegisterResponder("POST", fmt.Sprintf("https://api.cloudsmith.io/openid/%s/", namespace),
					httpmock.NewStringResponder(200, `{
						"token": "__test_token__"
				}`))
			case "gcp":
				httpmock.RegisterResponder("POST", "https://sts.googleapis.com/v1/token",
					httpmock.NewStringResponder(200, `{
						"access_token": "__test_token__",
						"expires_in": 3600,
						"token_type": "urn:ietf:params:oauth:token-type:access_token"
				}`))
			default:
				t.Fatal("unsupported provider in test case: " + tc.provider)
			}

			// ensure OIDC auth is enabled
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenUrl)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "sometoken")

			// create handler and capture log output
			var buf bytes.Buffer
			testhelpers.CaptureStandardLog(t, &buf)
			handler := tc.handlerFactory(tc.credentials)
			if tc.serviceIndexURL != "" {
				nugetHandler, ok := handler.(*NugetFeedHandler)
				if !assert.True(t, ok, "handler with a service index should be a NuGet handler") {
					return
				}
				discoverNugetFeed(t, nugetHandler, tc.serviceIndexURL, http.StatusOK, nugetV3Response(tc.resourceURL))
			}
			logContents := buf.String()

			// check expected log lines
			for _, expectedLine := range tc.expectedLogLines {
				assert.True(t, strings.Contains(logContents, expectedLine), "include log line: "+expectedLine)
			}

			// check URLs are authenticated
			for _, urlToAuth := range tc.urlsToAuthenticate {
				req := httptest.NewRequestWithContext(t.Context(), "GET", urlToAuth, nil)
				req = handleRequestAndClose(handler, req, nil)
				switch tc.provider {
				case "cloudsmith":
					assert.Equal(t, "__test_token__", req.Header.Get("X-Api-Key"), "package url: "+urlToAuth+" should include Cloudsmith API key")
					assert.Equal(t, "", req.Header.Get("Authorization"), "package url: "+urlToAuth+" should not include Authorization header for Cloudsmith")
				case "gcp":
					if strings.Contains(urlToAuth, "-docker.pkg.dev") {
						user, pass, ok := req.BasicAuth()
						assert.True(t, ok, "package url: "+urlToAuth+" should use Basic auth for GCP docker")
						assert.Equal(t, "oauth2accesstoken", user, "package url: "+urlToAuth+" should use oauth2accesstoken as username")
						assert.Equal(t, "__test_token__", pass, "package url: "+urlToAuth+" should include GCP token as password")
					} else {
						assertHasTokenAuth(t, req, "Bearer", "__test_token__", "package url: "+urlToAuth)
					}
				default:
					assertHasTokenAuth(t, req, "Bearer", "__test_token__", "package url: "+urlToAuth)
				}
			}
		})
	}
}

func TestNPMExplicitOIDCBeatsStaticProxyOnlyCredential(t *testing.T) {
	const tokenURL = "https://token.actions.example.com" //nolint:gosec // test URL
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenURL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder(http.MethodGet, tokenURL,
		httpmock.NewStringResponder(http.StatusOK, `{"count":1,"value":"github-token"}`))
	httpmock.RegisterResponder(
		http.MethodPost,
		"https://login.microsoftonline.com/explicit-tenant/oauth2/v2.0/token",
		httpmock.NewStringResponder(
			http.StatusOK,
			`{"access_token":"explicit-token","expires_in":3600,"token_type":"Bearer"}`,
		),
	)

	handler := NewNPMRegistryHandler(config.Credentials{
		{
			"type":       "npm_registry",
			"registry":   "https://npm.example.com",
			"token":      "automatic-user:automatic-token",
			"tenant-id":  "automatic-tenant",
			"client-id":  "automatic-client",
			"proxy-only": true,
		},
		{
			"type":      "npm_registry",
			"registry":  "https://npm.example.com/dependabot",
			"tenant-id": "explicit-tenant",
			"client-id": "explicit-client",
		},
	}, testOIDCClient)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://npm.example.com/dependabot/package", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", "explicit-token", "explicit OIDC credential")

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://npm.example.com/other/package", nil)
	assert.Nil(t, handler.oidcRegistry.CredentialForRequest(req), "proxy-only credential is not registered for OIDC")
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "automatic-user", "automatic-token", "static proxy-only credential")
}

func TestFailedExplicitOIDCBlocksProxyOnlyFallback(t *testing.T) {
	const tokenURL = "https://token.actions.example.com" //nolint:gosec // test URL
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenURL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder(http.MethodGet, tokenURL,
		httpmock.NewStringResponder(http.StatusInternalServerError, "failed"))

	oidcCredential := func(credentialType, field, location string) config.Credential {
		return config.Credential{
			"type":      credentialType,
			field:       location,
			"tenant-id": "failed-tenant",
			"client-id": "failed-client",
		}
	}
	tests := []struct {
		name        string
		requestURL  string
		credentials config.Credentials
		handler     func(config.Credentials) oidcHandler
	}{
		{
			name:       "npm",
			requestURL: "https://registry.example.com/dependabot/package",
			credentials: config.Credentials{
				{"type": "npm_registry", "registry": "https://registry.example.com", "token": "automatic-token", "proxy-only": true},
				oidcCredential("npm_registry", "registry", "https://registry.example.com/dependabot"),
			},
			handler: func(credentials config.Credentials) oidcHandler {
				return NewNPMRegistryHandler(credentials, testOIDCClient)
			},
		},
		{
			name:       "maven",
			requestURL: "https://registry.example.com/dependabot/package.jar",
			credentials: config.Credentials{
				{"type": "maven_repository", "host": "registry.example.com", "username": "automatic", "password": "token", "proxy-only": true},
				oidcCredential("maven_repository", "url", "https://registry.example.com/dependabot"),
			},
			handler: func(credentials config.Credentials) oidcHandler {
				return NewMavenRepositoryHandler(credentials, testOIDCClient)
			},
		},
		{
			name:       "rubygems",
			requestURL: "https://registry.example.com/dependabot/gem",
			credentials: config.Credentials{
				{"type": "rubygems_server", "host": "registry.example.com", "token": "automatic:token", "proxy-only": true},
				oidcCredential("rubygems_server", "url", "https://registry.example.com/dependabot"),
			},
			handler: func(credentials config.Credentials) oidcHandler {
				return NewRubyGemsServerHandler(credentials, testOIDCClient)
			},
		},
		{
			name:       "nuget",
			requestURL: "https://registry.example.com/dependabot/index.json",
			credentials: config.Credentials{
				{"type": "nuget_feed", "host": "registry.example.com", "username": "automatic", "password": "token", "proxy-only": true},
				oidcCredential("nuget_feed", "url", "https://registry.example.com/dependabot"),
			},
			handler: func(credentials config.Credentials) oidcHandler {
				return NewNugetFeedHandler(credentials, testOIDCClient)
			},
		},
		{
			name:       "docker",
			requestURL: "https://registry.example.com/v2/dependabot/core/manifests/latest",
			credentials: config.Credentials{
				{"type": "docker_registry", "registry": "registry.example.com", "username": "automatic", "password": "token", "proxy-only": true},
				{
					"type":      "docker_registry",
					"registry":  "registry.example.com",
					"url":       "https://registry.example.com/dependabot/core",
					"tenant-id": "failed-tenant",
					"client-id": "failed-client",
				},
			},
			handler: func(credentials config.Credentials) oidcHandler {
				return NewDockerRegistryHandler(credentials, testOIDCClient, nil)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, test.requestURL, nil)
			proxyCtx := &goproxy.ProxyCtx{}
			req = handleRequestAndClose(test.handler(test.credentials), req, proxyCtx)

			assertUnauthenticated(t, req, "failed OIDC blocks automatic auth")
			assert.Nil(t, proxyCtx.RoundTripper, "failed OIDC blocks automatic transport")
		})
	}
}

// TestPythonOIDCSimpleSuffixStripping verifies that Python index URLs ending
// with /simple or /+simple are normalized before OIDC registration, so that
// requests to sibling paths (e.g. /org/pkg/a) still match.
func TestPythonOIDCSimpleSuffixStripping(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	tenantA := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tenantB := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	clientId := "87654321-4321-4321-4321-210987654321"

	tokenUrl := "https://token.actions.example.com" //nolint:gosec // test URL
	httpmock.RegisterResponder("GET", tokenUrl,
		httpmock.NewStringResponder(200, `{"count":1,"value":"sometoken"}`))

	httpmock.RegisterResponder("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantA),
		httpmock.NewStringResponder(200, `{"access_token":"__token_A__","expires_in":3600,"token_type":"Bearer"}`))
	httpmock.RegisterResponder("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantB),
		httpmock.NewStringResponder(200, `{"access_token":"__token_B__","expires_in":3600,"token_type":"Bearer"}`))

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenUrl)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "sometoken")

	creds := config.Credentials{
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pkgs.example.com/org/feed-A/+simple/",
			"tenant-id": tenantA,
			"client-id": clientId,
		},
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pkgs.example.com/org/feed-B/simple",
			"tenant-id": tenantB,
			"client-id": clientId,
		},
	}

	handler := NewPythonIndexHandler(creds, testOIDCClient)

	// /+simple/ should be stripped → registered as /org/feed-A/
	reqA := httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.example.com/org/feed-A/pkg/a", nil)
	reqA = handleRequestAndClose(handler, reqA, nil)
	assertHasTokenAuth(t, reqA, "Bearer", "__token_A__", "feed-A request should use token A")

	// /simple should be stripped → registered as /org/feed-B/
	reqB := httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.example.com/org/feed-B/pkg/b", nil)
	reqB = handleRequestAndClose(handler, reqB, nil)
	assertHasTokenAuth(t, reqB, "Bearer", "__token_B__", "feed-B request should use token B")
}

func TestPythonOIDCAuthenticatesDiscoveredDownloadPrefix(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	tenantID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	clientID := "87654321-4321-4321-4321-210987654321"
	tokenURL := "https://token.actions.example.com" //nolint:gosec // test URL

	httpmock.RegisterResponder("GET", tokenURL,
		httpmock.NewStringResponder(200, `{"count":1,"value":"sometoken"}`))
	httpmock.RegisterResponder("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID),
		httpmock.NewStringResponder(200, `{"access_token":"__oidc_token__","expires_in":3600,"token_type":"Bearer"}`))

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenURL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "sometoken")

	handler := NewPythonIndexHandler(config.Credentials{
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pkgs.example.com/my-org/my-project/_packaging/my-feed/pypi/simple/",
			"tenant-id": tenantID,
			"client-id": clientID,
		},
	}, testOIDCClient)

	proxyCtx := &goproxy.ProxyCtx{}
	indexReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com/my-org/my-project/_packaging/my-feed/pypi/simple/my-package/",
		nil)

	indexReq = handleRequestAndClose(handler, indexReq, proxyCtx)
	assertHasTokenAuth(t, indexReq, "Bearer", "__oidc_token__", "simple index request should use OIDC token")

	indexResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
		Body: io.NopCloser(strings.NewReader(`
			<html><body>
				<a href="https://pkgs.example.com/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl#sha256=abc">
					my-package-1.0.0.whl
				</a>
			</body></html>
		`)),
	}
	indexResp = handler.HandleResponse(indexResp, proxyCtx)
	require.NoError(t, indexResp.Body.Close())

	downloadReq := httptest.NewRequestWithContext(t.Context(),
		"HEAD",
		"https://pkgs.example.com/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		nil)

	downloadReq = handleRequestAndClose(handler, downloadReq, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, downloadReq, "Bearer", "__oidc_token__", "discovered download request should use OIDC token")
}

// TestNPMOIDCSameHostDifferentPaths verifies that two npm OIDC credentials on
// the same host with different URL paths do not collide — each request is
// authenticated with the credential whose path is the longest prefix match.
func TestNPMOIDCSameHostDifferentPaths(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	tenantA := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tenantB := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	clientId := "87654321-4321-4321-4321-210987654321"

	tokenUrl := "https://token.actions.example.com" //nolint:gosec // test URL
	httpmock.RegisterResponder("GET", tokenUrl,
		httpmock.NewStringResponder(200, `{"count":1,"value":"sometoken"}`))

	httpmock.RegisterResponder("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantA),
		httpmock.NewStringResponder(200, `{"access_token":"__token_A__","expires_in":3600,"token_type":"Bearer"}`))
	httpmock.RegisterResponder("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantB),
		httpmock.NewStringResponder(200, `{"access_token":"__token_B__","expires_in":3600,"token_type":"Bearer"}`))

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenUrl)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "sometoken")

	creds := config.Credentials{
		config.Credential{
			"type":      "npm_registry",
			"url":       "https://pkgs.example.com/org/feed-A",
			"tenant-id": tenantA,
			"client-id": clientId,
		},
		config.Credential{
			"type":      "npm_registry",
			"url":       "https://pkgs.example.com/org/feed-B",
			"tenant-id": tenantB,
			"client-id": clientId,
		},
	}

	handler := NewNPMRegistryHandler(creds, testOIDCClient)

	// Request to feed-A path should get token A
	reqA := httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.example.com/org/feed-A/some-package", nil)
	reqA = handleRequestAndClose(handler, reqA, nil)
	assertHasTokenAuth(t, reqA, "Bearer", "__token_A__", "feed-A should use token A")

	// Request to feed-B path should get token B
	reqB := httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.example.com/org/feed-B/some-package", nil)
	reqB = handleRequestAndClose(handler, reqB, nil)
	assertHasTokenAuth(t, reqB, "Bearer", "__token_B__", "feed-B should use token B")
}

// TestTerraformOIDCSameHostDifferentPaths verifies that two terraform OIDC
// credentials on the same host with different URL paths do not collide — each
// request is authenticated with the credential whose path is the longest
// prefix match.
func TestTerraformOIDCSameHostDifferentPaths(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	tenantA := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tenantB := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	clientId := "87654321-4321-4321-4321-210987654321"

	tokenUrl := "https://token.actions.example.com" //nolint:gosec // test URL
	httpmock.RegisterResponder("GET", tokenUrl,
		httpmock.NewStringResponder(200, `{"count":1,"value":"sometoken"}`))

	// Two different Azure tenants → two different tokens
	httpmock.RegisterResponder("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantA),
		httpmock.NewStringResponder(200, `{"access_token":"__token_A__","expires_in":3600,"token_type":"Bearer"}`))
	httpmock.RegisterResponder("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantB),
		httpmock.NewStringResponder(200, `{"access_token":"__token_B__","expires_in":3600,"token_type":"Bearer"}`))

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenUrl)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "sometoken")

	creds := config.Credentials{
		config.Credential{
			"type":      "terraform_registry",
			"url":       "https://terraform.example.com/org/feed-A",
			"tenant-id": tenantA,
			"client-id": clientId,
		},
		config.Credential{
			"type":      "terraform_registry",
			"url":       "https://terraform.example.com/org/feed-B",
			"tenant-id": tenantB,
			"client-id": clientId,
		},
	}

	handler := NewTerraformRegistryHandler(creds, testOIDCClient)

	// Request to feed-A path should get token A
	reqA := httptest.NewRequestWithContext(t.Context(), "GET", "https://terraform.example.com/org/feed-A/v1/providers/org/name", nil)
	reqA = handleRequestAndClose(handler, reqA, nil)
	assertHasTokenAuth(t, reqA, "Bearer", "__token_A__", "feed-A should use token A")

	// Request to feed-B path should get token B
	reqB := httptest.NewRequestWithContext(t.Context(), "GET", "https://terraform.example.com/org/feed-B/v1/providers/org/name", nil)
	reqB = handleRequestAndClose(handler, reqB, nil)
	assertHasTokenAuth(t, reqB, "Bearer", "__token_B__", "feed-B should use token B")
}
