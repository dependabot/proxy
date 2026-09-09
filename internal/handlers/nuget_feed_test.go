package handlers

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/testhelpers"
)

type nugetRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f nugetRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestNugetFeedHandler(credentials config.Credentials) *NugetFeedHandler {
	return NewNugetFeedHandler(credentials, &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       http.NoBody,
			}, nil
		}),
	})
}

func TestNugetFeedHandler(t *testing.T) {
	dependabotToken := "123"
	deltaForceUser := "some-user"
	deltaForcePassword := "456"
	credentials := config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://pkgs.dev.azure.com/example/public/_packaging/some-feed/nuget/v3/index.json",
			"token": dependabotToken,
		},
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://pkgs.dev.azure.com/example/public/_packaging/some-feed2/nuget/v3/index.json",
			"token": fmt.Sprintf(":%s", dependabotToken),
		},
		config.Credential{
			"type": "nuget_feed",
			"url":  "https://api.nuget.org/v3/index.json",
		},
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://corp.dependabot.com/nuget/",
			"token": dependabotToken,
		},
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://corp.deltaforce.com:443/",
			"token": fmt.Sprintf("%s:%s", deltaForceUser, deltaForcePassword),
		},
		config.Credential{
			"type":     "nuget_feed",
			"host":     "pkgs.dev.azure.com",
			"username": deltaForceUser,
			"password": deltaForcePassword,
		},
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/v2",
			"token": dependabotToken,
		},
		config.Credential{
			"type": "nuget_feed",
			"url":  "https://nuget.example.com/auth-required/v3",
		},
	}

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	rsp := nugetV3IndexResponse{
		Resource: []nugetV3IndexResource{
			{
				ID:   "https://pkg-search.dependabot.com/query",
				Type: "PackageBaseAddress/3.1.0-this-is-trimmed",
			},
			{
				ID:   "https://pkg-search.dependabot.com/autocomplete",
				Type: "SearchAutocompleteService",
			},
			{
				ID:   "https://pkg-search.dependabot.com/{id}/{version}/ReportAbuse",
				Type: "ReportAbuseUriTemplate/3.0.0",
			},
		},
	}

	jsonResponder, err := httpmock.NewJsonResponder(200, rsp)
	require.NoError(t, err)
	httpmock.RegisterResponder("GET", "https://corp.dependabot.com/nuget/", jsonResponder)

	xmlResponse := `
<service xmlns="http://www.w3.org/2007/app" xmlns:atom="http://www.w3.org/2005/Atom" xml:base="https://redirected.example.com/v2">
  <workspace>
    <collection href="Packages">
      <atom:title type="text">Packages</atom:title>
    </collection>
  </workspace>
</service>
`
	xmlResponder := httpmock.NewStringResponder(200, xmlResponse)
	httpmock.RegisterResponder("GET", "https://nuget.example.com/v2", xmlResponder)
	httpmock.RegisterResponder("GET", "https://nuget.example.com/auth-required/v3", httpmock.NewStringResponder(401, "missing authentication"))

	azureDevOpsRsp := nugetV3IndexResponse{
		Resource: []nugetV3IndexResource{
			{
				ID:   "https://pkgs.dev.azure.com/example/public/_packaging/some-feed/nuget/v3/",
				Type: "PackageBaseAddress/3.1.0-this-is-trimmed",
			},
		},
	}

	azureDevOpsJsonResponder, err := httpmock.NewJsonResponder(200, azureDevOpsRsp)
	require.NoError(t, err)
	httpmock.RegisterResponder("GET", "https://pkgs.dev.azure.com/example/public/_packaging/some-feed/nuget/v3/index.json", azureDevOpsJsonResponder)

	azureDevOpsRsp2 := nugetV3IndexResponse{
		Resource: []nugetV3IndexResource{
			{
				ID:   "https://pkgs.dev.azure.com/example/public/_packaging/some-feed2/nuget/v3/",
				Type: "PackageBaseAddress/3.1.0-this-is-trimmed",
			},
		},
	}

	azureDevOpsJsonResponder2, err := httpmock.NewJsonResponder(200, azureDevOpsRsp2)
	require.NoError(t, err)
	httpmock.RegisterResponder("GET", "https://pkgs.dev.azure.com/example/public/_packaging/some-feed2/nuget/v3/index.json", azureDevOpsJsonResponder2)

	// Log for initial authentication contains appropriate information
	var buf bytes.Buffer
	testhelpers.CaptureStandardLog(t, &buf)
	handler := NewNugetFeedHandler(credentials, testOIDCClient)
	logContents := buf.String()
	assert.False(t, strings.Contains(logContents, "* authenticating nuget feed request (host: api.nuget.org, bearer auth)"), "don't authenticate a feed without a token or password")
	assert.NotContains(t, logContents, "https://nuget.example.com/auth-required/v3", "don't query a feed without usable credentials")

	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.dependabot.com/nuget", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "dependabot feed request")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.deltaforce.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce feed request")

	// Base URL listed in the v3 feed index
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pkg-search.dependabot.com/query", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "url listed in feed index")

	// Other URL listed in the v3 feed index
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pkg-search.dependabot.com/autocomplete", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "other url in feed index")

	// Template URL not authenticated
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pkg-search.dependabot.com/some.package/1.2.3/ReportAbuse", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "Template URL")

	// v2 API
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://nuget.example.com/v2/FindPackagesById()?Id='Some.Package'", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "authenticated v2 API")

	// v2 API - redirected
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://redirected.example.com/v2/FindPackagesById()?Id='Some.Package'", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "redirected authenticated v2 API")

	// Path mismatch
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.dependabot.com/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "Path mismatch")

	// Missing repo subdomain
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://dependabot.com/nuget", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequestWithContext(t.Context(), "GET", "http://corp.dependabot.com/nuget", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "dependabot feed http request")

	// HTTP, not HTTPS, path mismatch
	req = httptest.NewRequestWithContext(t.Context(), "GET", "http://corp.dependabot.com/feed", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "Path mismatch")

	// Not a GET request
	req = httptest.NewRequestWithContext(t.Context(), "POST", "https://corp.dependabot.com/nuget", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "post request")

	// Azure DevOps
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.dev.azure.com/dependabot/_packaging/dependabot/nuget/v3/index.json", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "Azure DevOps feed request")

	// Azure DevOps case insensitive
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://PKGS.dev.azure.com/dependabot/_packaging/dependabot/nuget/v3/index.json", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "Azure DevOps case insensitive feed request")

	// Reset buffer to catch log contents
	buf.Reset()
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.dev.azure.com/example/public/_packaging/some-feed/nuget/v3/some.package/index.json", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "", dependabotToken, "Azure DevOps token handling")
	logContents = buf.String()
	assert.True(t, strings.Contains(logContents, ", basic auth for Azure DevOps)"), "expected Azure DevOps token handling")

	// Check Azure token edge case in which it has a prepended ":" and is treated as a password successfully
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.dev.azure.com/example/public/_packaging/some-feed2/nuget/v3/some.package/index.json", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "", dependabotToken, "Azure DevOps token handling")
}

func TestShouldTreatTokenAsPassword(t *testing.T) {
	// Test case 1: URL with hostname "pkgs.dev.azure.com"
	url1, _ := url.Parse("https://pkgs.dev.azure.com/example")
	assert.True(t, shouldTreatTokenAsPassword(url1))

	// Test case 2: URL with visualsutudio hostname suffix
	url2, _ := url.Parse("https://example.pkgs.visualstudio.com/_packaging/")
	assert.True(t, shouldTreatTokenAsPassword(url2))

	// Test case 3: Similar but not exactly the same as test case 2; should fail
	url3, _ := url.Parse("sneaky.example.com/nuget.visualstudio.com/_packaging")
	assert.False(t, shouldTreatTokenAsPassword(url3))

	// Test case 3: URL with hostname not equal to "pkgs.dev.azure.com" and not matching the pattern
	url4, _ := url.Parse("https://example.com")
	assert.False(t, shouldTreatTokenAsPassword(url4))
}

func TestUrlsCanBeDeterminedFromNuGetFeeds(t *testing.T) {
	testCases := []struct {
		name              string
		url               string
		response          string
		expectedExtraUrls []string
	}{
		{"RegularV2API",
			"https://nuget.example.com/v2",
			`<service xmlns="http://www.w3.org/2007/app" xmlns:atom="http://www.w3.org/2005/Atom" xml:base="https://nuget.example.com/v2">
			  <workspace>
				<collection href="Packages">
				  <atom:title type="text">Packages</atom:title>
				</collection>
			  </workspace>
			</service>`,
			[]string{}},
		{"V2APIWithRedirect",
			"https://nuget.example.com/v2",
			`<service xmlns="http://www.w3.org/2007/app" xmlns:atom="http://www.w3.org/2005/Atom" xml:base="https://redirect.example.com/v2">
				<workspace>
				  <collection href="Packages">
					<atom:title type="text">Packages</atom:title>
				  </collection>
				</workspace>
			  </service>`,
			[]string{"https://redirect.example.com/v2"}},
		{"V2APIWithNoBase",
			"https://nuget.example.com/v2",
			`<service xmlns="http://www.w3.org/2007/app">
				<workspace>
				  <title xmlns="http://www.w3.org/2005/Atom">Default</title>
				  <collection href="Packages">
					<title xmlns="http://www.w3.org/2005/Atom">Packages</title>
				  </collection>
				</workspace>
			  </service>`,
			[]string{}},
		{"V3API",
			"https://nuget.example.com/v3",
			`{
				"version": "3.0.0",
				"resources": [
					{
						"@id": "https://nuget.example.com/v3/query",
						"@type": "SearchQueryService"
					},
					{
						"@id": "https://nuget.example.com/v3/unknown",
						"@type": "SomeUnknownServiceTypeButShouldStillBeIncluded"
					}
				]
			}`,
			[]string{"https://nuget.example.com/v3/query", "https://nuget.example.com/v3/unknown"}},
		{"WhitespaceResponse",
			"https://nuget.example.com/v3",
			" \n\t",
			[]string{}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			responseBody := []byte(tc.response)
			actualExtraUrls := extraUrlsFromSourceResponse(responseBody, tc.url)
			assert.ElementsMatch(t, tc.expectedExtraUrls, actualExtraUrls)
		})
	}
}

func TestExtraUrlsFromSourceResponseHandlesShortUnknownBody(t *testing.T) {
	assert.NotPanics(t, func() {
		assert.Empty(t, extraUrlsFromSourceResponse([]byte("x"), "https://nuget.example.com/index.json"))
	})
}

func TestExtraUrlsFromSourceResponseHandlesBlankBody(t *testing.T) {
	assert.Empty(t, extraUrlsFromSourceResponse(nil, "https://nuget.example.com/index.json"))
}

func TestExtraAuthenticatedURLsAreReportedInTheLog(t *testing.T) {
	credentials := config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/index.json",
			"token": "some-token",
		},
	}

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	jsonResponse := `{
		"version": "3.0.0",
		"resources": [
			{
				"@id": "https://nuget.example.com/v3/packages",
				"@type": "PackageBaseAddress/3.0.0"
			},
			{
				"@id": "https://nuget.example.com/v3/query",
				"@type": "SearchQueryService"
			},
			{
				"@id": "https://nuget.example.com/v3/unknown",
				"@type": "SomeUnknownServiceTypeButShouldStillBeIncluded/1.2.3"
			}
		]
	}`
	jsonResponder := httpmock.NewStringResponder(200, jsonResponse)
	httpmock.RegisterResponder("GET", "https://nuget.example.com/index.json", jsonResponder)

	var buf bytes.Buffer
	testhelpers.CaptureStandardLog(t, &buf)
	NewNugetFeedHandler(credentials, testOIDCClient)
	logContents := buf.String()

	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/packages"), "include PackageBaseAddress")
	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/query"), "include SearchQueryService")
	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/unknown"), "include SomeUnknownServiceTypeButShouldStillBeIncluded")
}

func TestNewNugetFeedHandlerDiscoversResources(t *testing.T) {
	const resourceURL = "https://cdn.example.com/packages"
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nugetDiscoveryResponse(resourceURL), nil
		}),
	}
	handler := NewNugetFeedHandler(config.Credentials{
		{"type": "nuget_feed", "url": "https://nuget.example.com/index.json", "token": "some-token"},
	}, client)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, resourceURL+"/example/1.0.0/example.nupkg", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "some-token", "resource discovered during construction")
}

func TestNugetFeedHandlerProxyOnlyCredentials(t *testing.T) {
	handler := NewNugetFeedHandler(config.Credentials{
		{
			"type":       "nuget_feed",
			"host":       "nuget.pkg.github.com",
			"username":   "x-access-token",
			"password":   "automatic-token",
			"proxy-only": true,
		},
		{
			"type":  "nuget_feed",
			"url":   "https://nuget.pkg.github.com/dependabot/index.json",
			"token": "explicit-token",
		},
	}, testOIDCClient)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://nuget.pkg.github.com/other/package/index.json", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "x-access-token", "automatic-token", "host-only automatic credential")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://nuget.pkg.github.com/other/package/index.json", nil)
	req.Header.Set("Authorization", authorizationPlaceholder)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "x-access-token", "automatic-token", "automatic credential replaces placeholder auth")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://nuget.pkg.github.com/other/package/index.json", nil)
	req.Header.Set("Authorization", "existing-token")
	req = handleRequestAndClose(handler, req, nil)
	assert.Equal(t, "existing-token", req.Header.Get("Authorization"), "automatic credential preserves request auth")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://nuget.pkg.github.com/dependabot/index.json", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", "explicit-token", "path-specific explicit credential")

	for _, requestURL := range []string{
		"http://nuget.pkg.github.com/other/package/index.json",
		"https://nuget.pkg.github.com:8443/other/package/index.json",
	} {
		req = httptest.NewRequestWithContext(t.Context(), "GET", requestURL, nil)
		req = handleRequestAndClose(handler, req, nil)
		assertUnauthenticated(t, req, "automatic credential destination safety")
	}
}

func TestNugetFeedHandlerPrefersMostSpecificURLCredential(t *testing.T) {
	broadCredential := config.Credential{
		"type":  "nuget_feed",
		"url":   "https://nuget.example.com/feed",
		"token": "broad-token",
	}
	specificCredential := config.Credential{
		"type":  "nuget_feed",
		"url":   "https://nuget.example.com/feed/specific",
		"token": "specific-token",
	}
	hostCredential := config.Credential{
		"type":     "nuget_feed",
		"host":     "nuget.example.com",
		"username": "host-user",
		"password": "host-password",
	}

	for _, credentials := range []config.Credentials{
		{broadCredential, specificCredential, hostCredential},
		{specificCredential, hostCredential, broadCredential},
	} {
		handler := newTestNugetFeedHandler(credentials)
		req := httptest.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			"https://nuget.example.com/feed/specific/package/index.json",
			nil,
		)
		req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
		assertHasTokenAuth(t, req, "Bearer", "specific-token", "most specific URL credential")
	}
}

func TestNugetFeedHandlerCanonicalURLKeys(t *testing.T) {
	equivalentEncodedURL := "https://nuget.example.com/f%65ed"
	equivalentPlainURL := "https://nuget.example.com/feed"
	encodedSlashURL := "https://nuget.example.com/feed%2fencoded"
	literalSlashURL := "https://nuget.example.com/feed/encoded"

	assert.Equal(t, nugetCredentialURLKey(equivalentEncodedURL), nugetCredentialURLKey(equivalentPlainURL))
	assert.Equal(t, nugetDiscoverySourceKey(equivalentEncodedURL), nugetDiscoverySourceKey(equivalentPlainURL))
	assert.NotEqual(t, nugetCredentialURLKey(encodedSlashURL), nugetCredentialURLKey(literalSlashURL))
	assert.NotEqual(t, nugetDiscoverySourceKey(encodedSlashURL), nugetDiscoverySourceKey(literalSlashURL))

	equivalentHandler := newTestNugetFeedHandler(config.Credentials{
		{"type": "nuget_feed", "url": equivalentEncodedURL, "token": "first-token"},
		{"type": "nuget_feed", "url": equivalentPlainURL, "token": "second-token"},
	})
	require.Len(t, equivalentHandler.credentials, 1)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, equivalentPlainURL+"/package/index.json", nil)
	req = handleRequestAndClose(equivalentHandler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "first-token", "first equivalent credential is retained")

	distinctHandler := newTestNugetFeedHandler(config.Credentials{
		{"type": "nuget_feed", "url": encodedSlashURL, "token": "encoded-token"},
		{"type": "nuget_feed", "url": literalSlashURL, "token": "literal-token"},
	})
	require.Len(t, distinctHandler.credentials, 2)

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, encodedSlashURL+"/package/index.json", nil)
	req = handleRequestAndClose(distinctHandler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "encoded-token", "encoded slash credential")

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, literalSlashURL+"/package/index.json", nil)
	req = handleRequestAndClose(distinctHandler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "literal-token", "literal path separator credential")
}

func TestNugetFeedHandlerIgnoresUnusableStaticCredentials(t *testing.T) {
	const credentialURL = "https://nuget.example.com/v3/index.json"
	unusableCredential := config.Credential{
		"type": "nuget_feed",
		"url":  credentialURL,
	}
	usableCredential := config.Credential{
		"type":  "nuget_feed",
		"url":   credentialURL,
		"token": "some-token",
	}

	var discoveryCalls atomic.Int32
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(*http.Request) (*http.Response, error) {
			discoveryCalls.Add(1)
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
		}),
	}
	handler := NewNugetFeedHandler(config.Credentials{unusableCredential}, client)
	assert.Empty(t, handler.credentials)
	assert.Zero(t, discoveryCalls.Load())

	for _, credentials := range []config.Credentials{
		{unusableCredential, usableCredential},
		{usableCredential, unusableCredential},
	} {
		handler = newTestNugetFeedHandler(credentials)
		require.Len(t, handler.credentials, 1)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, credentialURL, nil)
		req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
		assertHasTokenAuth(t, req, "Bearer", "some-token", "usable duplicate credential")
	}
}

func TestNugetFeedHandlerConfiguredCredentialPrecedesDiscoveredCredential(t *testing.T) {
	const configuredURL = "https://cdn.example.com/packages"
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Hostname() == "source.example.com" {
				return nugetDiscoveryResponse(configuredURL), nil
			}
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
		}),
	}
	handler := NewNugetFeedHandler(config.Credentials{
		{"type": "nuget_feed", "url": "https://source.example.com/index.json", "token": "discovery-token"},
		{"type": "nuget_feed", "url": configuredURL, "token": "configured-token"},
	}, client)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, configuredURL+"/example/index.json", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "configured-token", "configured credential")
}

func TestNugetFeedHandlerUnusableCredentialDoesNotBlockDiscoveredCredential(t *testing.T) {
	const resourceURL = "https://cdn.example.com/packages"
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nugetDiscoveryResponse(resourceURL), nil
		}),
	}
	handler := NewNugetFeedHandler(config.Credentials{
		{"type": "nuget_feed", "url": resourceURL},
		{"type": "nuget_feed", "url": "https://source.example.com/index.json", "token": "some-token"},
	}, client)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, resourceURL+"/example/index.json", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "some-token", "discovered credential replacing unusable entry")
}

func TestNugetFeedHandlerLogsIgnoredDuplicateResourceURL(t *testing.T) {
	const resourceURL = "https://shared.example.com/packages"
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nugetDiscoveryResponse(resourceURL), nil
		}),
	}
	var buf bytes.Buffer
	testhelpers.CaptureStandardLog(t, &buf)
	handler := NewNugetFeedHandler(config.Credentials{
		{"type": "nuget_feed", "url": "https://first.example.com/index.json", "token": "first-token"},
		{"type": "nuget_feed", "url": "https://second.example.com/index.json", "token": "second-token"},
	}, client)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, resourceURL+"/example/index.json", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "first-token", "first credential registered for shared resource")
	assert.Contains(t, buf.String(), "skipping duplicate NuGet credential URL because it is already registered: "+resourceURL)
}

func TestNugetFeedHandlerDiscoversFeedsConcurrentlyInCredentialOrder(t *testing.T) {
	firstRequestStarted := make(chan struct{})
	secondRequestCompleted := make(chan struct{})
	releaseFirstRequest := make(chan struct{})
	var closeFirstStarted sync.Once
	var closeSecondCompleted sync.Once

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Hostname() {
			case "first.example.com":
				closeFirstStarted.Do(func() { close(firstRequestStarted) })
				<-releaseFirstRequest
				return nugetDiscoveryResponse("https://first-cdn.example.com/packages"), nil
			case "second.example.com":
				closeSecondCompleted.Do(func() { close(secondRequestCompleted) })
				return nugetDiscoveryResponse("https://second-cdn.example.com/packages"), nil
			default:
				return nil, fmt.Errorf("unexpected NuGet discovery host %s", req.URL.Hostname())
			}
		}),
	}

	handlerResult := make(chan *NugetFeedHandler, 1)
	go func() {
		handlerResult <- NewNugetFeedHandler(config.Credentials{
			{
				"type":  "nuget_feed",
				"url":   "https://first.example.com/index.json",
				"token": "first-token",
			},
			{
				"type":  "nuget_feed",
				"url":   "https://second.example.com/index.json",
				"token": "second-token",
			},
		}, client)
	}()

	select {
	case <-firstRequestStarted:
	case <-time.After(time.Second):
		close(releaseFirstRequest)
		require.FailNow(t, "first NuGet discovery request did not start")
	}
	select {
	case <-secondRequestCompleted:
	case <-time.After(time.Second):
		close(releaseFirstRequest)
		require.FailNow(t, "second NuGet discovery request did not complete while the first was blocked")
	}
	close(releaseFirstRequest)

	var handler *NugetFeedHandler
	select {
	case handler = <-handlerResult:
	case <-time.After(time.Second):
		require.FailNow(t, "NuGet feed handler construction did not complete")
	}

	require.Len(t, handler.credentials, 4)
	assert.Equal(t, []string{
		"https://first.example.com/index.json",
		"https://second.example.com/index.json",
		"https://first-cdn.example.com/packages",
		"https://second-cdn.example.com/packages",
	}, []string{
		handler.credentials[0].url,
		handler.credentials[1].url,
		handler.credentials[2].url,
		handler.credentials[3].url,
	})
}

func TestNugetFeedHandlerKeepsHTTPAndHTTPSDiscoverySourcesDistinct(t *testing.T) {
	var httpCalls atomic.Int32
	var httpsCalls atomic.Int32
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Scheme == "http" {
				httpCalls.Add(1)
				return nugetDiscoveryResponse("https://http-cdn.example.com/packages"), nil
			}
			httpsCalls.Add(1)
			return nugetDiscoveryResponse("https://https-cdn.example.com/packages"), nil
		}),
	}
	handler := NewNugetFeedHandler(config.Credentials{
		{"type": "nuget_feed", "url": "http://nuget.example.com/index.json", "token": "http-token"},
		{"type": "nuget_feed", "url": "https://nuget.example.com/index.json", "token": "https-token"},
	}, client)

	assert.Equal(t, int32(1), httpCalls.Load())
	assert.Equal(t, int32(1), httpsCalls.Load())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://http-cdn.example.com/packages/example/index.json", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "http-token", "resource discovered from HTTP source")

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://https-cdn.example.com/packages/example/index.json", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "https-token", "resource discovered from HTTPS source")
}

func TestNugetFeedHandlerConcurrentDiscoveryIsDeduplicated(t *testing.T) {
	const sourceCount = 50
	const resourceURL = "https://shared.example.com/packages"
	var calls atomic.Int32
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nugetDiscoveryResponse(resourceURL), nil
		}),
	}
	credentials := make(config.Credentials, 0, sourceCount)
	for i := range sourceCount {
		credentials = append(credentials, config.Credential{
			"type":  "nuget_feed",
			"url":   fmt.Sprintf("https://source-%d.example.com/index.json", i),
			"token": fmt.Sprintf("token-%d", i),
		})
	}

	handler := NewNugetFeedHandler(credentials, client)

	assert.Equal(t, int32(sourceCount), calls.Load())
	require.Len(t, handler.credentials, sourceCount+1)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, resourceURL+"/example/index.json", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "token-0", "first discovered credential")
}

func TestNugetFeedHandlerDiscoversThroughCrossOriginRedirectWithoutLeakingCredentials(t *testing.T) {
	const resourceURL = "https://cdn.example.com/packages"
	var firstRedirectAuth string
	var finalRedirectAuth string
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.URL.Hostname() == "nuget.example.com":
				return nugetRedirectResponse("https://redirect.example.com/index.json"), nil
			case req.URL.Path == "/index.json":
				firstRedirectAuth = req.Header.Get("Authorization")
				return nugetRedirectResponse("/v3/index.json"), nil
			case req.URL.Path == "/v3/index.json":
				finalRedirectAuth = req.Header.Get("Authorization")
				return nugetDiscoveryResponse(resourceURL), nil
			default:
				return nil, fmt.Errorf("unexpected discovery URL %s", req.URL)
			}
		}),
	}
	handler := NewNugetFeedHandler(config.Credentials{
		{"type": "nuget_feed", "url": "https://nuget.example.com/index.json", "token": "some-token"},
	}, client)

	assert.Empty(t, firstRedirectAuth)
	assert.Empty(t, finalRedirectAuth)
	for _, redirectURL := range []string{
		"https://redirect.example.com/index.json",
		"https://redirect.example.com/v3/index.json",
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, redirectURL, nil)
		req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
		assertUnauthenticated(t, req, "cross-origin service-index redirect")
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, resourceURL+"/example/index.json", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "some-token", "resource discovered after cross-origin redirect")
}

func TestNugetFeedHandlerAuthenticatesSameOriginServiceIndexRedirect(t *testing.T) {
	testCases := []struct {
		name          string
		configuredURL string
		location      string
		redirectURL   string
	}{
		{
			name:          "absolute path",
			configuredURL: "https://nuget.example.com/index.json",
			location:      "/v3/index.json",
			redirectURL:   "https://nuget.example.com/v3/index.json",
		},
		{
			name:          "relative path",
			configuredURL: "https://nuget.example.com/feed/index.json",
			location:      "v3/index.json",
			redirectURL:   "https://nuget.example.com/feed/v3/index.json",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			const resourceURL = "https://cdn.example.com/packages"
			var redirectAuth string
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: nugetRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.String() == testCase.configuredURL {
						return nugetRedirectResponse(testCase.location), nil
					}
					if req.URL.String() == testCase.redirectURL {
						redirectAuth = req.Header.Get("Authorization")
						return nugetDiscoveryResponse(resourceURL), nil
					}
					return nil, fmt.Errorf("unexpected discovery URL %s", req.URL)
				}),
			}
			handler := NewNugetFeedHandler(config.Credentials{
				{"type": "nuget_feed", "url": testCase.configuredURL, "token": "some-token"},
			}, client)

			assert.Equal(t, "Bearer some-token", redirectAuth)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testCase.redirectURL, nil)
			req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
			assertHasTokenAuth(t, req, "Bearer", "some-token", "same-origin service-index redirect")
		})
	}
}

func TestNugetFeedHandlerResolvesRelativeRedirectAgainstConfiguredServiceIndexURL(t *testing.T) {
	const configuredURL = "https://nuget.example.com/feed/index.json"
	const redirectURL = "https://nuget.example.com/feed/next.json"
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: nugetRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == configuredURL {
				return nugetRedirectResponse("next.json"), nil
			}
			if req.URL.String() == redirectURL {
				return nugetDiscoveryResponse("https://cdn.example.com/packages"), nil
			}
			return nil, fmt.Errorf("unexpected discovery URL %s", req.URL)
		}),
	}
	handler := NewNugetFeedHandler(config.Credentials{
		{"type": "nuget_feed", "url": configuredURL, "token": "some-token"},
	}, client)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, redirectURL, nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "some-token", "relative service-index redirect")
}

func TestNugetFeedHandlerSkipsDiscoveryFromUnsuccessfulResponse(t *testing.T) {
	for _, statusCode := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNoContent,
		http.StatusResetContent,
		http.StatusFound,
		http.StatusInternalServerError,
	} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: nugetRoundTripperFunc(func(*http.Request) (*http.Response, error) {
					response := nugetDiscoveryResponse("https://cdn.example.com/packages")
					response.StatusCode = statusCode
					return response, nil
				}),
			}

			handler := NewNugetFeedHandler(config.Credentials{
				{
					"type":  "nuget_feed",
					"url":   "https://nuget.example.com/index.json",
					"token": "some-token",
				},
			}, client)

			require.Len(t, handler.credentials, 1)
			assert.Equal(t, "https://nuget.example.com/index.json", handler.credentials[0].url)
		})
	}
}

func nugetRedirectResponse(location string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusTemporaryRedirect,
		Header:     http.Header{"Location": []string{location}},
		Body:       http.NoBody,
	}
}

func nugetDiscoveryResponse(resourceURL string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(fmt.Sprintf(
			`{"version":"3.0.0","resources":[{"@id":%q,"@type":"PackageBaseAddress/3.0.0"}]}`,
			resourceURL,
		))),
	}
}
