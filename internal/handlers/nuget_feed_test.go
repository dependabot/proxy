package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/testhelpers"
)

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

	xmlResponse := `
<service xmlns="http://www.w3.org/2007/app" xmlns:atom="http://www.w3.org/2005/Atom" xml:base="https://redirected.example.com/v2">
  <workspace>
    <collection href="Packages">
      <atom:title type="text">Packages</atom:title>
    </collection>
  </workspace>
</service>
`

	azureDevOpsRsp := nugetV3IndexResponse{
		Resource: []nugetV3IndexResource{
			{
				ID:   "https://pkgs.dev.azure.com/example/public/_packaging/some-feed/nuget/v3/",
				Type: "PackageBaseAddress/3.1.0-this-is-trimmed",
			},
		},
	}

	azureDevOpsRsp2 := nugetV3IndexResponse{
		Resource: []nugetV3IndexResource{
			{
				ID:   "https://pkgs.dev.azure.com/example/public/_packaging/some-feed2/nuget/v3/",
				Type: "PackageBaseAddress/3.1.0-this-is-trimmed",
			},
		},
	}

	var buf bytes.Buffer
	testhelpers.CaptureStandardLog(t, &buf)
	handler := newTestNugetFeedHandler(credentials)

	discoverNugetFeed(t, handler, "https://corp.dependabot.com/nuget/", http.StatusOK, mustMarshalJSON(t, rsp))
	discoverNugetFeed(t, handler, "https://nuget.example.com/v2", http.StatusOK, xmlResponse)
	discoverNugetFeed(t, handler, "https://pkgs.dev.azure.com/example/public/_packaging/some-feed/nuget/v3/index.json", http.StatusOK, mustMarshalJSON(t, azureDevOpsRsp))
	discoverNugetFeed(t, handler, "https://pkgs.dev.azure.com/example/public/_packaging/some-feed2/nuget/v3/index.json", http.StatusOK, mustMarshalJSON(t, azureDevOpsRsp2))

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
	logContents := buf.String()
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
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			responseBody := []byte(tc.response)
			actualExtraUrls := extraUrlsFromSourceResponse(responseBody, tc.url)
			assert.ElementsMatch(t, tc.expectedExtraUrls, actualExtraUrls)
		})
	}
}

func TestExtraAuthenticatedURLsAreReportedInTheLog(t *testing.T) {
	credentials := config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/index.json",
			"token": "some-token",
		},
	}

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

	var buf bytes.Buffer
	testhelpers.CaptureStandardLog(t, &buf)
	handler := newTestNugetFeedHandler(credentials)
	discoverNugetFeed(t, handler, "https://nuget.example.com/index.json", http.StatusOK, jsonResponse)
	logContents := buf.String()

	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/packages"), "include PackageBaseAddress")
	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/query"), "include SearchQueryService")
	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/unknown"), "include SomeUnknownServiceTypeButShouldStillBeIncluded")
}

func TestNewNugetFeedHandlerDoesNotMakeHTTPRequests(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://unreachable.example.com/index.json", "some-token"),
	})

	assert.Zero(t, httpmock.GetTotalCallCount())
}

func TestNugetFeedHandlerDiscoversFromPreparedResponse(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://nuget.example.com/index.json", "some-token"),
	})
	discoverNugetFeed(t, handler, "https://nuget.example.com/index.json", http.StatusOK,
		nugetV3Response("https://cdn.example.com/packages"))

	packageReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cdn.example.com/packages/example/1.0.0/example.nupkg", nil)
	packageReq = handleRequestAndClose(handler, packageReq, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, packageReq, "Bearer", "some-token", "resource learned from prepared response")
}

func TestNugetFeedHandlerSkipsDiscoveryFromUnsuccessfulResponse(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://nuget.example.com/index.json", "some-token"),
	})
	discoverNugetFeed(t, handler, "https://nuget.example.com/index.json", http.StatusUnauthorized,
		nugetV3Response("https://cdn.example.com/packages"))

	packageReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cdn.example.com/packages/example/index.json", nil)
	packageReq = handleRequestAndClose(handler, packageReq, &goproxy.ProxyCtx{})
	assertUnauthenticated(t, packageReq, "resource from unsuccessful response")
}

func TestNugetFeedHandlerLeavesBodylessResponseUnchanged(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://nuget.example.com/index.json", "some-token"),
	})

	for _, statusCode := range []int{http.StatusNoContent, http.StatusResetContent} {
		proxyCtx := &goproxy.ProxyCtx{}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/index.json", nil)
		prepareRequestAndClose(handler, req, proxyCtx)
		resp := &http.Response{StatusCode: statusCode, Body: http.NoBody}

		resp = handler.HandleResponse(resp, proxyCtx)

		assert.True(t, resp.Body == http.NoBody)
		require.NoError(t, resp.Body.Close())
	}
}

func TestNugetFeedHandlerReplaysBodyAfterReadError(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://nuget.example.com/index.json", "some-token"),
	})
	proxyCtx := &goproxy.ProxyCtx{}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/index.json", nil)
	prepareRequestAndClose(handler, req, proxyCtx)
	originalBody := &readErrorThenData{
		first: []byte("first"),
		rest:  strings.NewReader("second"),
	}
	resp := &http.Response{StatusCode: http.StatusOK, Body: originalBody}

	resp = handler.HandleResponse(resp, proxyCtx)
	replayed, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "firstsecond", string(replayed))
	require.NoError(t, resp.Body.Close())
}

func TestNugetFeedHandlerOnlyDiscoversFromConfiguredServiceIndex(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://nuget.example.com/v3/", "some-token"),
	})
	proxyCtx := &goproxy.ProxyCtx{}
	packageReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/v3/some-package/index.json", nil)
	prepareRequestAndClose(handler, packageReq, proxyCtx)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(nugetV3Response("https://untrusted.example.com/packages"))),
	}
	handleResponseAndClose(handler, resp, proxyCtx)

	untrustedReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://untrusted.example.com/packages/example/index.json", nil)
	untrustedReq = handleRequestAndClose(handler, untrustedReq, &goproxy.ProxyCtx{})
	assertUnauthenticated(t, untrustedReq, "resource from non-index response")
}

func TestNugetFeedHandlerRequiresConfiguredServiceIndexSchemeForDiscovery(t *testing.T) {
	testCases := []struct {
		name              string
		configuredURL     string
		requestedURL      string
		expectCredentials bool
	}{
		{
			name:              "HTTPS source does not trust HTTP response",
			configuredURL:     "https://nuget.example.com/v3/index.json",
			requestedURL:      "http://nuget.example.com/v3/index.json",
			expectCredentials: false,
		},
		{
			name:              "HTTP source does not trust HTTPS response",
			configuredURL:     "http://nuget.example.com/v3/index.json",
			requestedURL:      "https://nuget.example.com/v3/index.json",
			expectCredentials: false,
		},
		{
			name:              "scheme-less source trusts HTTP response",
			configuredURL:     "nuget.example.com/v3/index.json",
			requestedURL:      "http://nuget.example.com/v3/index.json",
			expectCredentials: true,
		},
		{
			name:              "scheme-less source trusts HTTPS response",
			configuredURL:     "nuget.example.com/v3/index.json",
			requestedURL:      "https://nuget.example.com/v3/index.json",
			expectCredentials: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := newTestNugetFeedHandler(config.Credentials{
				testNugetFeedCredential(testCase.configuredURL, "some-token"),
			})
			proxyCtx := &goproxy.ProxyCtx{}
			indexReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testCase.requestedURL, nil)
			prepareRequestAndClose(handler, indexReq, proxyCtx)
			handleResponseAndClose(handler, &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(nugetV3Response("https://attacker.example.com/packages"))),
			}, proxyCtx)

			packageReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://attacker.example.com/packages/example/index.json", nil)
			packageReq = handleRequestAndClose(handler, packageReq, &goproxy.ProxyCtx{})
			if testCase.expectCredentials {
				assertHasTokenAuth(t, packageReq, "Bearer", "some-token", "resource from scheme-less service index")
			} else {
				assertUnauthenticated(t, packageReq, "resource from mismatched service-index scheme")
			}
		})
	}
}

func TestNugetFeedHandlerKeepsHTTPAndHTTPSDiscoverySourcesDistinct(t *testing.T) {
	httpCredential := testNugetFeedCredential("http://nuget.example.com/v3/index.json", "http-token")
	httpsCredential := testNugetFeedCredential("https://nuget.example.com/v3/index.json", "https-token")

	for _, credentials := range []config.Credentials{
		{httpCredential, httpsCredential},
		{httpsCredential, httpCredential},
	} {
		handler := newTestNugetFeedHandler(credentials)
		discoverNugetFeed(t, handler, "http://nuget.example.com/v3/index.json", http.StatusOK,
			nugetV3Response("https://http-resource.example.com/packages"))
		discoverNugetFeed(t, handler, "https://nuget.example.com/v3/index.json", http.StatusOK,
			nugetV3Response("https://https-resource.example.com/packages"))

		httpResourceReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://http-resource.example.com/packages/example/index.json", nil)
		httpResourceReq = handleRequestAndClose(handler, httpResourceReq, &goproxy.ProxyCtx{})
		assertHasTokenAuth(t, httpResourceReq, "Bearer", "http-token", "resource discovered from HTTP index")

		httpsResourceReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://https-resource.example.com/packages/example/index.json", nil)
		httpsResourceReq = handleRequestAndClose(handler, httpsResourceReq, &goproxy.ProxyCtx{})
		assertHasTokenAuth(t, httpsResourceReq, "Bearer", "https-token", "resource discovered from HTTPS index")
	}
}

func TestNugetFeedHandlerConcurrentDiscoveryIsDeduplicated(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://nuget.example.com/index.json", "some-token"),
	})
	const workers = 50
	responseBody := nugetV3Response("https://cdn.example.com/packages")
	start := make(chan struct{})
	ctx := t.Context()
	var waitGroup sync.WaitGroup
	for range workers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			proxyCtx := &goproxy.ProxyCtx{}
			indexReq := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://nuget.example.com/index.json", nil)
			indexReq = prepareRequestAndClose(handler, indexReq, proxyCtx)
			handleRequestAndClose(handler, indexReq, proxyCtx)
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(responseBody)),
			}
			resp = handler.HandleResponse(resp, proxyCtx)
			if err := resp.Body.Close(); err != nil {
				panic(err)
			}

			packageReq := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://cdn.example.com/packages/example/index.json", nil)
			handleRequestAndClose(handler, packageReq, &goproxy.ProxyCtx{})
		}()
	}
	close(start)
	waitGroup.Wait()

	handler.credentialsMutex.RLock()
	defer handler.credentialsMutex.RUnlock()
	assert.Len(t, handler.credentials, 2)
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
		testNugetFeedCredential(equivalentEncodedURL, "first-token"),
		testNugetFeedCredential(equivalentPlainURL, "second-token"),
	})
	assert.Len(t, equivalentHandler.credentials, 1, "equivalent encodings deduplicate first-wins")
	assert.Len(t, equivalentHandler.discoverySources, 1, "equivalent discovery sources deduplicate")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, equivalentPlainURL+"/package/index.json", nil)
	req = handleRequestAndClose(equivalentHandler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "first-token", "first equivalent credential is retained")

	distinctHandler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential(encodedSlashURL, "encoded-token"),
		testNugetFeedCredential(literalSlashURL, "literal-token"),
	})
	assert.Len(t, distinctHandler.credentials, 2, "encoded slash remains distinct from a path separator")
	assert.Len(t, distinctHandler.discoverySources, 2, "distinct paths retain separate discovery sources")

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, encodedSlashURL+"/package/index.json", nil)
	req = handleRequestAndClose(distinctHandler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "encoded-token", "encoded slash credential")

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, literalSlashURL+"/package/index.json", nil)
	req = handleRequestAndClose(distinctHandler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "literal-token", "literal path separator credential")
}

func TestNugetFeedHandlerIgnoresUnusableStaticCredentials(t *testing.T) {
	usableCredential := testNugetFeedCredential("https://nuget.example.com/v3/index.json", "some-token")
	unusableCredential := config.Credential{
		"type": "nuget_feed",
		"url":  "https://nuget.example.com/v3/index.json",
	}

	for _, credentials := range []config.Credentials{
		{unusableCredential, usableCredential},
		{usableCredential, unusableCredential},
	} {
		handler := newTestNugetFeedHandler(credentials)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/v3/index.json", nil)
		req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
		assertHasTokenAuth(t, req, "Bearer", "some-token", "usable duplicate credential")
	}
}

func TestNugetFeedHandlerLogsIgnoredDuplicateResourceURL(t *testing.T) {
	var buf bytes.Buffer
	testhelpers.CaptureStandardLog(t, &buf)
	handler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://first.example.com/index.json", "first-token"),
		testNugetFeedCredential("https://second.example.com/index.json", "second-token"),
	})

	const resourceURL = "https://shared.example.com/packages"
	discoverNugetFeed(t, handler, "https://first.example.com/index.json", http.StatusOK, nugetV3Response(resourceURL))
	discoverNugetFeed(t, handler, "https://second.example.com/index.json", http.StatusOK, nugetV3Response(resourceURL))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, resourceURL+"/example/index.json", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "first-token", "first credential registered for shared resource")
	assert.Contains(t, buf.String(), "skipping duplicate NuGet credential URL because it is already registered: "+resourceURL)
}

func TestNugetFeedHandlerUnusableCredentialDoesNotBlockDiscoveredCredential(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
		config.Credential{
			"type": "nuget_feed",
			"url":  "https://cdn.example.com/packages",
		},
		testNugetFeedCredential("https://nuget.example.com/v3/index.json", "some-token"),
	})
	discoverNugetFeed(t, handler, "https://nuget.example.com/v3/index.json", http.StatusOK,
		nugetV3Response("https://cdn.example.com/packages"))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cdn.example.com/packages/example/index.json", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "some-token", "discovered credential replacing unusable entry")
}

func TestNugetFeedHandlerPrefersMostSpecificURLCredential(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://nuget.example.com/feed", "broad-token"),
		testNugetFeedCredential("https://nuget.example.com/feed/specific", "specific-token"),
		config.Credential{
			"type":     "nuget_feed",
			"host":     "nuget.example.com",
			"username": "host-user",
			"password": "host-password",
		},
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/feed/specific/package/index.json", nil)
	req = handleRequestAndClose(handler, req, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, req, "Bearer", "specific-token", "most specific URL credential")
}

func TestNugetFeedHandlerProxyOnlyCredentials(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
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
	})

	assert.Len(t, handler.discoverySources, 1, "proxy-only credentials do not create discovery sources")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.pkg.github.com/other/package/index.json", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "x-access-token", "automatic-token", "host-only automatic credential")

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.pkg.github.com/other/package/index.json", nil)
	req.Header.Set("Authorization", authorizationPlaceholder)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "x-access-token", "automatic-token", "automatic credential replaces placeholder auth")

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.pkg.github.com/other/package/index.json", nil)
	req.Header.Set("Authorization", "Bearer caller-token")
	req = handleRequestAndClose(handler, req, nil)
	assert.Equal(t, "Bearer caller-token", req.Header.Get("Authorization"), "automatic credential preserves request auth")

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.pkg.github.com/dependabot/index.json", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "Bearer", "explicit-token", "path-specific explicit credential")

	for _, requestURL := range []string{
		"http://nuget.pkg.github.com/other/package/index.json",
		"https://nuget.pkg.github.com:8443/other/package/index.json",
	} {
		req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
		req = handleRequestAndClose(handler, req, nil)
		assertUnauthenticated(t, req, "automatic credential destination safety")
	}

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.pkg.github.example/other/package/index.json", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "automatic credential host mismatch")
}

func TestNugetFeedHandlerDiscoversThroughCrossOriginRedirectWithoutLeakingCredentials(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://nuget.example.com/index.json", "some-token"),
	})

	initialCtx := &goproxy.ProxyCtx{}
	initialReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/index.json", nil)
	initialReq = prepareRequestAndClose(handler, initialReq, initialCtx)
	initialReq = handleRequestAndClose(handler, initialReq, initialCtx)
	assertHasTokenAuth(t, initialReq, "Bearer", "some-token", "configured service index")
	handleResponseAndClose(handler, &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": []string{"https://redirect.example.com/index.json"}},
	}, initialCtx)

	redirectCtx := &goproxy.ProxyCtx{}
	redirectReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://redirect.example.com/index.json", nil)
	redirectReq = prepareRequestAndClose(handler, redirectReq, redirectCtx)
	redirectReq = handleRequestAndClose(handler, redirectReq, redirectCtx)
	assertUnauthenticated(t, redirectReq, "cross-origin service-index redirect")
	handleResponseAndClose(handler, &http.Response{
		StatusCode: http.StatusTemporaryRedirect,
		Header:     http.Header{"Location": []string{"/v3/index.json"}},
	}, redirectCtx)

	finalCtx := &goproxy.ProxyCtx{}
	finalReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://redirect.example.com/v3/index.json", nil)
	finalReq = prepareRequestAndClose(handler, finalReq, finalCtx)
	finalReq = handleRequestAndClose(handler, finalReq, finalCtx)
	assertUnauthenticated(t, finalReq, "redirect after cross-origin service-index redirect")
	finalResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(nugetV3Response("https://cdn.example.com/packages"))),
	}
	handleResponseAndClose(handler, finalResp, finalCtx)

	packageReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cdn.example.com/packages/example/index.json", nil)
	packageReq = handleRequestAndClose(handler, packageReq, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, packageReq, "Bearer", "some-token", "resource learned through cross-origin redirect")
}

func TestNugetFeedHandlerAuthenticatesSameOriginServiceIndexRedirect(t *testing.T) {
	handler := newTestNugetFeedHandler(config.Credentials{
		testNugetFeedCredential("https://nuget.example.com/index.json", "some-token"),
	})

	initialCtx := &goproxy.ProxyCtx{}
	initialReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/index.json", nil)
	initialReq = prepareRequestAndClose(handler, initialReq, initialCtx)
	handleRequestAndClose(handler, initialReq, initialCtx)
	handleResponseAndClose(handler, &http.Response{
		StatusCode: http.StatusTemporaryRedirect,
		Header:     http.Header{"Location": []string{"/v3/index.json"}},
	}, initialCtx)

	redirectReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/v3/index.json", nil)
	redirectReq = handleRequestAndClose(handler, redirectReq, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, redirectReq, "Bearer", "some-token", "same-origin service-index redirect")
}

func TestNugetFeedHandlerResolvesRelativeRedirectAgainstRequestedServiceIndexURL(t *testing.T) {
	testCases := []struct {
		name          string
		configuredURL string
		requestedURL  string
		redirectURL   string
	}{
		{
			name:          "configured URL has trailing slash",
			configuredURL: "https://nuget.example.com/v3/",
			requestedURL:  "https://nuget.example.com/v3",
			redirectURL:   "https://nuget.example.com/next.json",
		},
		{
			name:          "requested URL has trailing slash",
			configuredURL: "https://nuget.example.com/v3",
			requestedURL:  "https://nuget.example.com/v3/",
			redirectURL:   "https://nuget.example.com/v3/next.json",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := newTestNugetFeedHandler(config.Credentials{
				testNugetFeedCredential(testCase.configuredURL, "some-token"),
			})

			initialCtx := &goproxy.ProxyCtx{}
			initialReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testCase.requestedURL, nil)
			prepareRequestAndClose(handler, initialReq, initialCtx)
			handleResponseAndClose(handler, &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": []string{"next.json"}},
			}, initialCtx)

			redirectCtx := &goproxy.ProxyCtx{}
			redirectReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testCase.redirectURL, nil)
			prepareRequestAndClose(handler, redirectReq, redirectCtx)
			handleResponseAndClose(handler, &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(nugetV3Response("https://cdn.example.com/packages"))),
			}, redirectCtx)

			packageReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cdn.example.com/packages/example/index.json", nil)
			packageReq = handleRequestAndClose(handler, packageReq, &goproxy.ProxyCtx{})
			assertHasTokenAuth(t, packageReq, "Bearer", "some-token", "resource learned through relative redirect")
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

func discoverNugetFeed(t *testing.T, handler *NugetFeedHandler, sourceURL string, statusCode int, responseBody string) {
	t.Helper()
	proxyCtx := &goproxy.ProxyCtx{}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, sourceURL, nil)
	req = prepareRequestAndClose(handler, req, proxyCtx)
	handleRequestAndClose(handler, req, proxyCtx)

	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(responseBody)),
	}
	resp = handler.HandleResponse(resp, proxyCtx)

	replayedBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, responseBody, string(replayedBody))
	require.NoError(t, resp.Body.Close())
}

func testNugetFeedCredential(rawURL, token string) config.Credential {
	return config.Credential{
		"type":  "nuget_feed",
		"url":   rawURL,
		"token": token,
	}
}

func nugetV3Response(resourceURL string) string {
	return fmt.Sprintf(`{"version":"3.0.0","resources":[{"@id":%q,"@type":"PackageBaseAddress/3.0.0"}]}`, resourceURL)
}

func mustMarshalJSON(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	require.NoError(t, err)
	return string(body)
}

type readErrorThenData struct {
	first []byte
	rest  io.Reader
}

func (r *readErrorThenData) Read(p []byte) (int, error) {
	if r.first != nil {
		n := copy(p, r.first)
		r.first = nil
		return n, assert.AnError
	}
	return r.rest.Read(p)
}

func (r *readErrorThenData) Close() error { return nil }

func newTestNugetFeedHandler(credentials config.Credentials) *NugetFeedHandler {
	return NewNugetFeedHandler(credentials, testOIDCClient)
}
