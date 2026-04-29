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

const (
	testRegion   = "us-east-1"
	testTenantID = "12345678-1234-1234-1234-123456789012"
	testClientID = "87654321-4321-4321-4321-210987654321"
)

// oidcProviderFields returns the OIDC-specific credential fields for each provider.
// These are identical across all ecosystems — only the URL/registry/host fields vary.
func oidcProviderFields(provider string) map[string]string {
	switch provider {
	case "aws":
		return map[string]string{
			"aws-region":   testRegion,
			"account-id":   "123456789012",
			"role-name":    "MyRole",
			"domain":       "my-domain",
			"domain-owner": "9876543210",
		}
	case "azure":
		return map[string]string{
			"tenant-id": testTenantID,
			"client-id": testClientID,
		}
	case "jfrog":
		return map[string]string{
			"jfrog-oidc-provider-name": "proxy-test",
		}
	case "cloudsmith":
		return map[string]string{
			"namespace":    "space",
			"service-slug": "repo",
			"audience":     "my-audience",
		}
	case "gcp":
		return map[string]string{
			"workload-identity-provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
		}
	default:
		panic("unknown provider: " + provider)
	}
}

// providerVariant defines what varies for each OIDC provider within an ecosystem.
type providerVariant struct {
	provider   string
	testName   string            // optional override for the test name (e.g., "Docker with URL")
	credFields map[string]string // ecosystem-specific fields (type + URL key)
	// If nil, generated as "registered {provider} OIDC credentials for {logLabel}: {first URL value}"
	expectedLogLines []string
	// If nil, generated as first URL value + "/some-package"
	urlsToAuthenticate []string
	urlMocks           []mockHttpRequest
}

// oidcTestCase is the same struct used by the test runner.
type oidcTestCase struct {
	name               string
	provider           string
	handlerFactory     func(creds config.Credentials) oidcHandler
	credentials        config.Credentials
	urlMocks           []mockHttpRequest
	expectedLogLines   []string
	urlsToAuthenticate []string
}

// buildEcosystemCases generates test cases for an ecosystem across all providers.
func buildEcosystemCases(
	defaultName string,
	factory func(config.Credentials) oidcHandler,
	logLabel string,
	variants []providerVariant,
) []oidcTestCase {
	cases := make([]oidcTestCase, 0, len(variants))
	for _, v := range variants {
		// Build credential by merging ecosystem fields + provider fields
		cred := config.Credential{}
		for k, val := range v.credFields {
			cred[k] = val
		}
		for k, val := range oidcProviderFields(v.provider) {
			cred[k] = val
		}

		name := defaultName
		if v.testName != "" {
			name = v.testName
		}

		// Derive expected log lines if not explicit
		logLines := v.expectedLogLines
		if logLines == nil {
			// Find the first URL-like value from credFields (skip "type")
			target := firstURLValue(v.credFields)
			logLines = []string{
				fmt.Sprintf("registered %s OIDC credentials for %s: %s", v.provider, logLabel, target),
			}
		}

		// Derive auth URLs if not explicit
		authURLs := v.urlsToAuthenticate
		if authURLs == nil {
			target := firstURLValue(v.credFields)
			authURLs = []string{target + "/some-package"}
		}

		cases = append(cases, oidcTestCase{
			name:               name,
			provider:           v.provider,
			handlerFactory:     factory,
			credentials:        config.Credentials{cred},
			urlMocks:           v.urlMocks,
			expectedLogLines:   logLines,
			urlsToAuthenticate: authURLs,
		})
	}
	return cases
}

// firstURLValue returns the first URL-like credential field value (skips "type").
func firstURLValue(fields map[string]string) string {
	// Check common URL keys in priority order
	for _, key := range []string{"url", "registry", "host", "index-url"} {
		if v, ok := fields[key]; ok {
			return v
		}
	}
	return ""
}

func TestOIDCURLsAreAuthenticated(t *testing.T) {
	var testCases []oidcTestCase

	// Cargo
	testCases = append(testCases, buildEcosystemCases("Cargo",
		func(creds config.Credentials) oidcHandler { return NewCargoRegistryHandler(creds) },
		"cargo registry",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "cargo_registry", "url": "https://cargo.example.com/packages"}},
			{provider: "azure", credFields: map[string]string{"type": "cargo_registry", "url": "https://cargo.example.com/packages"}},
			{provider: "jfrog", credFields: map[string]string{"type": "cargo_registry", "url": "https://jfrog.example.com/packages"}},
			{provider: "cloudsmith", credFields: map[string]string{"type": "cargo_registry", "url": "https://cloudsmith.example.com"}},
			{provider: "gcp", credFields: map[string]string{"type": "cargo_registry", "url": "https://us-central1-cargo.pkg.dev/my-project/my-repo"}},
		},
	)...)

	// Composer
	testCases = append(testCases, buildEcosystemCases("Composer",
		func(creds config.Credentials) oidcHandler { return NewComposerHandler(creds) },
		"composer repository",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "composer_repository", "registry": "https://composer.example.com"}},
			{provider: "azure", credFields: map[string]string{"type": "composer_repository", "registry": "https://composer.example.com"}},
			{provider: "jfrog", credFields: map[string]string{"type": "composer_repository", "registry": "https://jfrog.example.com", "url": "https://jfrog.example.com"}},
			{provider: "cloudsmith", credFields: map[string]string{"type": "composer_repository", "registry": "https://cloudsmith.example.com"}},
			{provider: "gcp", credFields: map[string]string{"type": "composer_repository", "registry": "https://us-central1-composer.pkg.dev/my-project/my-repo"}},
		},
	)...)

	// Docker
	dockerFactory := func(creds config.Credentials) oidcHandler {
		return NewDockerRegistryHandler(creds, &http.Transport{}, nil)
	}
	testCases = append(testCases, buildEcosystemCases("Docker",
		dockerFactory, "docker registry",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "docker_registry", "registry": "https://docker.example.com"}},
			{provider: "azure", credFields: map[string]string{"type": "docker_registry", "registry": "https://docker.example.com"}},
			{
				provider:         "jfrog",
				testName:         "Docker with URL",
				credFields:       map[string]string{"type": "docker_registry", "url": "https://jfrog.example.com"},
				expectedLogLines: []string{"registered jfrog OIDC credentials for docker registry: jfrog.example.com"},
			},
			{provider: "cloudsmith", credFields: map[string]string{"type": "docker_registry", "registry": "https://cloudsmith.example.com"}},
			{provider: "gcp", credFields: map[string]string{"type": "docker_registry", "registry": "https://us-central1-docker.pkg.dev"}},
		},
	)...)

	// Go proxy
	testCases = append(testCases, buildEcosystemCases("Go proxy",
		func(creds config.Credentials) oidcHandler { return NewGoProxyServerHandler(creds) },
		"goproxy server",
		[]providerVariant{
			{
				provider:           "aws",
				credFields:         map[string]string{"type": "goproxy_server", "url": "https://goproxy.example.com"},
				urlsToAuthenticate: []string{"https://goproxy.example.com/packages/some-package"},
			},
			{
				provider:           "azure",
				testName:           "Go proxy with host",
				credFields:         map[string]string{"type": "goproxy_server", "host": "goproxy.example.com"},
				expectedLogLines:   []string{"registered azure OIDC credentials for goproxy server: goproxy.example.com"},
				urlsToAuthenticate: []string{"https://goproxy.example.com/packages/some-package"},
			},
			{
				provider:           "jfrog",
				credFields:         map[string]string{"type": "goproxy_server", "url": "https://jfrog.example.com"},
				urlsToAuthenticate: []string{"https://jfrog.example.com/packages/some-package"},
			},
			{
				provider:           "cloudsmith",
				credFields:         map[string]string{"type": "goproxy_server", "url": "https://cloudsmith.example.com"},
				urlsToAuthenticate: []string{"https://cloudsmith.example.com/some-package"},
			},
			{
				provider:           "gcp",
				credFields:         map[string]string{"type": "goproxy_server", "url": "https://us-central1-go.pkg.dev/my-project/my-repo"},
				urlsToAuthenticate: []string{"https://us-central1-go.pkg.dev/my-project/my-repo/some-package"},
			},
		},
	)...)

	// Helm registry
	testCases = append(testCases, buildEcosystemCases("Helm registry",
		func(creds config.Credentials) oidcHandler { return NewHelmRegistryHandler(creds) },
		"helm registry",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "helm_registry", "registry": "https://helm.example.com"}},
			{provider: "azure", credFields: map[string]string{"type": "helm_registry", "registry": "https://helm.example.com"}},
			{
				provider:         "jfrog",
				testName:         "Helm registry with url",
				credFields:       map[string]string{"type": "helm_registry", "url": "https://jfrog.example.com"},
				expectedLogLines: []string{"registered jfrog OIDC credentials for helm registry: jfrog.example.com"},
			},
			{provider: "cloudsmith", credFields: map[string]string{"type": "helm_registry", "registry": "https://cloudsmith.example.com"}},
			{provider: "gcp", credFields: map[string]string{"type": "helm_registry", "registry": "https://us-central1-helm.pkg.dev/my-project/my-repo"}},
		},
	)...)

	// Hex
	testCases = append(testCases, buildEcosystemCases("Hex",
		func(creds config.Credentials) oidcHandler { return NewHexRepositoryHandler(creds) },
		"hex repository",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "hex_repository", "url": "https://hex.example.com"}},
			{provider: "azure", credFields: map[string]string{"type": "hex_repository", "url": "https://hex.example.com"}},
			{provider: "jfrog", credFields: map[string]string{"type": "hex_repository", "url": "https://jfrog.example.com"}},
			{provider: "cloudsmith", credFields: map[string]string{"type": "hex_repository", "url": "https://cloudsmith.example.com"}},
			{provider: "gcp", credFields: map[string]string{"type": "hex_repository", "url": "https://us-central1-hex.pkg.dev/my-project/my-repo"}},
		},
	)...)

	// Maven
	testCases = append(testCases, buildEcosystemCases("Maven",
		func(creds config.Credentials) oidcHandler { return NewMavenRepositoryHandler(creds) },
		"maven repository",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "maven_repository", "url": "https://maven.example.com/packages"}},
			{provider: "azure", credFields: map[string]string{"type": "maven_repository", "url": "https://maven.example.com/packages"}},
			{provider: "jfrog", credFields: map[string]string{"type": "maven_repository", "url": "https://jfrog.example.com/packages"}},
			{provider: "cloudsmith", credFields: map[string]string{"type": "maven_repository", "url": "https://cloudsmith.example.com"}},
			{provider: "gcp", credFields: map[string]string{"type": "maven_repository", "url": "https://us-central1-maven.pkg.dev/my-project/my-repo"}},
		},
	)...)

	// NPM
	testCases = append(testCases, buildEcosystemCases("NPM",
		func(creds config.Credentials) oidcHandler { return NewNPMRegistryHandler(creds) },
		"npm registry",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "npm_registry", "url": "https://npm.example.com"}},
			{provider: "azure", credFields: map[string]string{"type": "npm_registry", "url": "https://npm.example.com"}},
			{provider: "jfrog", credFields: map[string]string{"type": "npm_registry", "url": "https://jfrog.example.com"}},
			{provider: "cloudsmith", credFields: map[string]string{"type": "npm_registry", "url": "https://cloudsmith.example.com"}},
			{provider: "gcp", credFields: map[string]string{"type": "npm_registry", "url": "https://us-central1-npm.pkg.dev/my-project/my-repo"}},
		},
	)...)

	// NuGet — has URL mocks for service index discovery and extra log/auth URLs
	nugetFactory := func(creds config.Credentials) oidcHandler { return NewNugetFeedHandler(creds) }
	nugetMock := func(baseURL, resourceURL string) []mockHttpRequest {
		return []mockHttpRequest{{
			verb:     "GET",
			url:      baseURL,
			response: fmt.Sprintf(`{"version":"3.0.0","resources":[{"@id":"%s","@type":"PackageBaseAddress/3.0.0"}]}`, resourceURL),
		}}
	}
	nugetVariant := func(provider, baseURL, resourceURL string) providerVariant {
		return providerVariant{
			provider:   provider,
			credFields: map[string]string{"type": "nuget_feed", "url": baseURL},
			urlMocks:   nugetMock(baseURL, resourceURL),
			expectedLogLines: []string{
				fmt.Sprintf("registered %s OIDC credentials for nuget feed: %s", provider, baseURL),
				fmt.Sprintf("registered %s OIDC credentials for nuget resource: %s", provider, resourceURL),
			},
			urlsToAuthenticate: []string{
				baseURL,
				resourceURL + "/some.package/index.json",
			},
		}
	}
	testCases = append(testCases, buildEcosystemCases("NuGet", nugetFactory, "nuget feed",
		[]providerVariant{
			nugetVariant("aws", "https://nuget.example.com/index.json", "https://nuget.example.com/v3/packages"),
			nugetVariant("azure", "https://nuget.example.com/index.json", "https://nuget.example.com/v3/packages"),
			nugetVariant("jfrog", "https://jfrog.example.com/index.json", "https://jfrog.example.com/v3/packages"),
			nugetVariant("cloudsmith", "https://cloudsmith.example.com/v3/index.json", "https://cloudsmith.example.com/v3/packages"),
			nugetVariant("gcp", "https://us-central1-nuget.pkg.dev/my-project/my-repo/index.json", "https://us-central1-nuget.pkg.dev/my-project/my-repo/v3/packages"),
		},
	)...)

	// Pub
	testCases = append(testCases, buildEcosystemCases("Pub",
		func(creds config.Credentials) oidcHandler { return NewPubRepositoryHandler(creds) },
		"pub repository",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "pub_repository", "url": "https://pub.example.com"}},
			{provider: "azure", credFields: map[string]string{"type": "pub_repository", "url": "https://pub.example.com"}},
			{provider: "jfrog", credFields: map[string]string{"type": "pub_repository", "url": "https://jfrog.example.com"}},
			{provider: "cloudsmith", credFields: map[string]string{"type": "pub_repository", "url": "https://cloudsmith.example.com"}},
			{provider: "gcp", credFields: map[string]string{"type": "pub_repository", "url": "https://us-central1-pub.pkg.dev/my-project/my-repo"}},
		},
	)...)

	// Python — GCP uses index-url with /simple suffix stripping for log target
	testCases = append(testCases, buildEcosystemCases("Python",
		func(creds config.Credentials) oidcHandler { return NewPythonIndexHandler(creds) },
		"python index",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "python_index", "url": "https://python.example.com"}},
			{provider: "azure", credFields: map[string]string{"type": "python_index", "url": "https://python.example.com"}},
			{provider: "jfrog", credFields: map[string]string{"type": "python_index", "url": "https://jfrog.example.com"}},
			{provider: "cloudsmith", credFields: map[string]string{"type": "python_index", "url": "https://cloudsmith.example.com"}},
			{
				provider:   "gcp",
				credFields: map[string]string{"type": "python_index", "index-url": "https://us-central1-python.pkg.dev/my-project/my-repo/simple"},
				expectedLogLines: []string{
					"registered gcp OIDC credentials for python index: https://us-central1-python.pkg.dev/my-project/my-repo/",
				},
				urlsToAuthenticate: []string{
					"https://us-central1-python.pkg.dev/my-project/my-repo/simple/some-package",
				},
			},
		},
	)...)

	// RubyGems — uses "host" as primary URL key; jfrog/cloudsmith/gcp also set "url"
	testCases = append(testCases, buildEcosystemCases("RubyGems",
		func(creds config.Credentials) oidcHandler { return NewRubyGemsServerHandler(creds) },
		"rubygems server",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "rubygems_server", "host": "https://rubygems.example.com"}},
			{provider: "azure", credFields: map[string]string{"type": "rubygems_server", "host": "https://rubygems.example.com"}},
			{provider: "jfrog", credFields: map[string]string{"type": "rubygems_server", "url": "https://jfrog.example.com", "host": "https://jfrog.example.com"}},
			{provider: "cloudsmith", credFields: map[string]string{"type": "rubygems_server", "url": "https://cloudsmith.example.com", "host": "https://cloudsmith.example.com"}},
			{provider: "gcp", credFields: map[string]string{"type": "rubygems_server", "url": "https://us-central1-ruby.pkg.dev/my-project/my-repo", "host": "https://us-central1-ruby.pkg.dev/my-project/my-repo"}},
		},
	)...)

	// Terraform — azure uses "host" instead of "url"
	testCases = append(testCases, buildEcosystemCases("Terraform",
		func(creds config.Credentials) oidcHandler { return NewTerraformRegistryHandler(creds) },
		"terraform registry",
		[]providerVariant{
			{provider: "aws", credFields: map[string]string{"type": "terraform_registry", "url": "https://terraform.example.com"}},
			{
				provider:           "azure",
				testName:           "Terraform with host",
				credFields:         map[string]string{"type": "terraform_registry", "host": "https://terraform.example.com"},
				expectedLogLines:   []string{"registered azure OIDC credentials for terraform registry: https://terraform.example.com"},
				urlsToAuthenticate: []string{"https://terraform.example.com/some-package"},
			},
			{provider: "jfrog", credFields: map[string]string{"type": "terraform_registry", "url": "https://jfrog.example.com"}},
			{provider: "cloudsmith", credFields: map[string]string{"type": "terraform_registry", "url": "https://cloudsmith.example.com"}},
			{provider: "gcp", credFields: map[string]string{"type": "terraform_registry", "url": "https://us-central1-terraform.pkg.dev/my-project/my-repo"}},
		},
	)...)

	// Run all test cases
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

			// mock provider token exchange endpoints
			switch tc.provider {
			case "aws":
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
				httpmock.RegisterResponder("POST",
					fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", testTenantID),
					httpmock.NewStringResponder(200, `{
"access_token": "__test_token__",
"expires_in": 3600,
"token_type": "Bearer"
}`))
			case "jfrog":
				httpmock.RegisterResponder("POST", "https://jfrog.example.com/access/api/v1/oidc/token", httpmock.NewStringResponder(200, `{
"access_token": "__test_token__",
"expires_in": 3600
}`))
			case "cloudsmith":
				namespace := tc.credentials[0].GetString("namespace")
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

	handler := NewPythonIndexHandler(creds)

	// /+simple/ should be stripped → registered as /org/feed-A/
	reqA := httptest.NewRequest("GET", "https://pkgs.example.com/org/feed-A/pkg/a", nil)
	reqA = handleRequestAndClose(handler, reqA, nil)
	assertHasTokenAuth(t, reqA, "Bearer", "__token_A__", "feed-A request should use token A")

	// /simple should be stripped → registered as /org/feed-B/
	reqB := httptest.NewRequest("GET", "https://pkgs.example.com/org/feed-B/pkg/b", nil)
	reqB = handleRequestAndClose(handler, reqB, nil)
	assertHasTokenAuth(t, reqB, "Bearer", "__token_B__", "feed-B request should use token B")
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

	handler := NewNPMRegistryHandler(creds)

	// Request to feed-A path should get token A
	reqA := httptest.NewRequest("GET", "https://pkgs.example.com/org/feed-A/some-package", nil)
	reqA = handleRequestAndClose(handler, reqA, nil)
	assertHasTokenAuth(t, reqA, "Bearer", "__token_A__", "feed-A should use token A")

	// Request to feed-B path should get token B
	reqB := httptest.NewRequest("GET", "https://pkgs.example.com/org/feed-B/some-package", nil)
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

	handler := NewTerraformRegistryHandler(creds)

	// Request to feed-A path should get token A
	reqA := httptest.NewRequest("GET", "https://terraform.example.com/org/feed-A/v1/providers/org/name", nil)
	reqA = handleRequestAndClose(handler, reqA, nil)
	assertHasTokenAuth(t, reqA, "Bearer", "__token_A__", "feed-A should use token A")

	// Request to feed-B path should get token B
	reqB := httptest.NewRequest("GET", "https://terraform.example.com/org/feed-B/v1/providers/org/name", nil)
	reqB = handleRequestAndClose(handler, reqB, nil)
	assertHasTokenAuth(t, reqB, "Bearer", "__token_B__", "feed-B should use token B")
}
