package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	log.SetOutput(&buf)
	handler := NewNugetFeedHandler(credentials)

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
	log.SetOutput(&buf)
	handler := NewNugetFeedHandler(credentials)
	discoverNugetFeed(t, handler, "https://nuget.example.com/index.json", http.StatusOK, jsonResponse)
	logContents := buf.String()

	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/packages"), "include PackageBaseAddress")
	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/query"), "include SearchQueryService")
	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/unknown"), "include SomeUnknownServiceTypeButShouldStillBeIncluded")
}

func TestNewNugetFeedHandlerDoesNotMakeHTTPRequests(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	NewNugetFeedHandler(config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://unreachable.example.com/index.json",
			"token": "some-token",
		},
	})

	assert.Zero(t, httpmock.GetTotalCallCount())
	assert.Contains(t, buf.String(), "registered NuGet service index for deferred discovery: https://unreachable.example.com/index.json")
}

func TestNugetFeedHandlerDiscoversFromPreparedResponse(t *testing.T) {
	handler := NewNugetFeedHandler(config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/index.json",
			"token": "some-token",
		},
	})
	proxyCtx := &goproxy.ProxyCtx{}
	indexReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/index.json", nil)
	handler.PrepareRequest(indexReq, proxyCtx)

	indexResp := &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(
			`{"version":"3.0.0","resources":[{"@id":"https://cdn.example.com/packages","@type":"PackageBaseAddress/3.0.0"}]}`,
		)),
	}
	handler.HandleResponse(indexResp, proxyCtx)

	packageReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cdn.example.com/packages/example/1.0.0/example.nupkg", nil)
	packageReq = handleRequestAndClose(handler, packageReq, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, packageReq, "Bearer", "some-token", "resource learned from prepared response")
}

func TestNugetFeedHandlerSkipsDiscoveryFromUnsuccessfulResponse(t *testing.T) {
	handler := NewNugetFeedHandler(config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/index.json",
			"token": "some-token",
		},
	})
	discoverNugetFeed(t, handler, "https://nuget.example.com/index.json", http.StatusUnauthorized,
		`{"version":"3.0.0","resources":[{"@id":"https://cdn.example.com/packages","@type":"PackageBaseAddress/3.0.0"}]}`)

	packageReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cdn.example.com/packages/example/index.json", nil)
	packageReq = handleRequestAndClose(handler, packageReq, &goproxy.ProxyCtx{})
	assertUnauthenticated(t, packageReq, "resource from unsuccessful response")
}

func TestNugetFeedHandlerLeavesBodylessResponseUnchanged(t *testing.T) {
	handler := NewNugetFeedHandler(config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/index.json",
			"token": "some-token",
		},
	})

	for _, statusCode := range []int{http.StatusNoContent, http.StatusResetContent} {
		proxyCtx := &goproxy.ProxyCtx{}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/index.json", nil)
		handler.PrepareRequest(req, proxyCtx)
		resp := &http.Response{StatusCode: statusCode, Body: http.NoBody}

		handler.HandleResponse(resp, proxyCtx)

		assert.True(t, resp.Body == http.NoBody)
	}
}

func TestNugetFeedHandlerReplaysBodyAfterReadError(t *testing.T) {
	handler := NewNugetFeedHandler(config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/index.json",
			"token": "some-token",
		},
	})
	proxyCtx := &goproxy.ProxyCtx{}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/index.json", nil)
	handler.PrepareRequest(req, proxyCtx)
	originalBody := &readErrorThenData{
		first: []byte("first"),
		rest:  strings.NewReader("second"),
	}
	resp := &http.Response{StatusCode: http.StatusOK, Body: originalBody}

	handler.HandleResponse(resp, proxyCtx)
	replayed, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "firstsecond", string(replayed))
}

func TestNugetFeedHandlerOnlyDiscoversFromConfiguredServiceIndex(t *testing.T) {
	handler := NewNugetFeedHandler(config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/v3/",
			"token": "some-token",
		},
	})
	proxyCtx := &goproxy.ProxyCtx{}
	packageReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/v3/some-package/index.json", nil)
	handler.PrepareRequest(packageReq, proxyCtx)
	packageReq = handleRequestAndClose(handler, packageReq, proxyCtx)
	assertHasTokenAuth(t, packageReq, "Bearer", "some-token", "package under configured feed")

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(
			`{"version":"3.0.0","resources":[{"@id":"https://untrusted.example.com/packages","@type":"PackageBaseAddress/3.0.0"}]}`,
		)),
	}
	handler.HandleResponse(resp, proxyCtx)

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
			handler := NewNugetFeedHandler(config.Credentials{
				config.Credential{
					"type":  "nuget_feed",
					"url":   testCase.configuredURL,
					"token": "some-token",
				},
			})
			proxyCtx := &goproxy.ProxyCtx{}
			indexReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testCase.requestedURL, nil)
			handler.PrepareRequest(indexReq, proxyCtx)
			handler.HandleResponse(&http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(
					`{"version":"3.0.0","resources":[{"@id":"https://attacker.example.com/packages","@type":"PackageBaseAddress/3.0.0"}]}`,
				)),
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

func TestNugetFeedHandlerConcurrentDiscoveryIsDeduplicated(t *testing.T) {
	handler := NewNugetFeedHandler(config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/index.json",
			"token": "some-token",
		},
	})
	const workers = 50
	responseBody := `{"version":"3.0.0","resources":[{"@id":"https://cdn.example.com/packages","@type":"PackageBaseAddress/3.0.0"}]}`
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for range workers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			proxyCtx := &goproxy.ProxyCtx{}
			indexReq := httptest.NewRequest(http.MethodGet, "https://nuget.example.com/index.json", nil)
			handler.PrepareRequest(indexReq, proxyCtx)
			handler.HandleRequest(indexReq, proxyCtx)
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(responseBody)),
			}
			handler.HandleResponse(resp, proxyCtx)
			resp.Body.Close()

			packageReq := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/packages/example/index.json", nil)
			handler.HandleRequest(packageReq, &goproxy.ProxyCtx{})
		}()
	}
	close(start)
	waitGroup.Wait()

	handler.credentialsMutex.RLock()
	defer handler.credentialsMutex.RUnlock()
	assert.Len(t, handler.credentials, 2)
}

func TestNugetFeedHandlerPrefersMostSpecificURLCredential(t *testing.T) {
	handler := NewNugetFeedHandler(config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/feed",
			"token": "broad-token",
		},
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/feed/specific",
			"token": "specific-token",
		},
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

func TestNugetFeedHandlerDiscoversThroughCrossOriginRedirectWithoutLeakingCredentials(t *testing.T) {
	handler := NewNugetFeedHandler(config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/index.json",
			"token": "some-token",
		},
	})

	initialCtx := &goproxy.ProxyCtx{}
	initialReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/index.json", nil)
	handler.PrepareRequest(initialReq, initialCtx)
	initialReq = handleRequestAndClose(handler, initialReq, initialCtx)
	assertHasTokenAuth(t, initialReq, "Bearer", "some-token", "configured service index")
	handler.HandleResponse(&http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": []string{"https://redirect.example.com/index.json"}},
	}, initialCtx)

	redirectCtx := &goproxy.ProxyCtx{}
	redirectReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://redirect.example.com/index.json", nil)
	handler.PrepareRequest(redirectReq, redirectCtx)
	redirectReq = handleRequestAndClose(handler, redirectReq, redirectCtx)
	assertUnauthenticated(t, redirectReq, "cross-origin service-index redirect")
	handler.HandleResponse(&http.Response{
		StatusCode: http.StatusTemporaryRedirect,
		Header:     http.Header{"Location": []string{"/v3/index.json"}},
	}, redirectCtx)

	finalCtx := &goproxy.ProxyCtx{}
	finalReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://redirect.example.com/v3/index.json", nil)
	handler.PrepareRequest(finalReq, finalCtx)
	finalReq = handleRequestAndClose(handler, finalReq, finalCtx)
	assertUnauthenticated(t, finalReq, "redirect after cross-origin service-index redirect")
	finalResp := &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(
			`{"version":"3.0.0","resources":[{"@id":"https://cdn.example.com/packages","@type":"PackageBaseAddress/3.0.0"}]}`,
		)),
	}
	handler.HandleResponse(finalResp, finalCtx)

	packageReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://cdn.example.com/packages/example/index.json", nil)
	packageReq = handleRequestAndClose(handler, packageReq, &goproxy.ProxyCtx{})
	assertHasTokenAuth(t, packageReq, "Bearer", "some-token", "resource learned through cross-origin redirect")
}

func TestNugetFeedHandlerAuthenticatesSameOriginServiceIndexRedirect(t *testing.T) {
	handler := NewNugetFeedHandler(config.Credentials{
		config.Credential{
			"type":  "nuget_feed",
			"url":   "https://nuget.example.com/index.json",
			"token": "some-token",
		},
	})

	initialCtx := &goproxy.ProxyCtx{}
	initialReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://nuget.example.com/index.json", nil)
	handler.PrepareRequest(initialReq, initialCtx)
	handleRequestAndClose(handler, initialReq, initialCtx)
	handler.HandleResponse(&http.Response{
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
			handler := NewNugetFeedHandler(config.Credentials{
				config.Credential{
					"type":  "nuget_feed",
					"url":   testCase.configuredURL,
					"token": "some-token",
				},
			})

			initialCtx := &goproxy.ProxyCtx{}
			initialReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testCase.requestedURL, nil)
			handler.PrepareRequest(initialReq, initialCtx)
			handler.HandleResponse(&http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": []string{"next.json"}},
			}, initialCtx)

			redirectCtx := &goproxy.ProxyCtx{}
			redirectReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testCase.redirectURL, nil)
			handler.PrepareRequest(redirectReq, redirectCtx)
			handler.HandleResponse(&http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(
					`{"version":"3.0.0","resources":[{"@id":"https://cdn.example.com/packages","@type":"PackageBaseAddress/3.0.0"}]}`,
				)),
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

func TestExtraUrlsFromSourceResponseLogsBlankBody(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

	assert.Empty(t, extraUrlsFromSourceResponse(nil, "https://nuget.example.com/index.json"))
	assert.Contains(t, buf.String(), "empty API response from NuGet feed https://nuget.example.com/index.json")
}

func discoverNugetFeed(t *testing.T, handler *NugetFeedHandler, sourceURL string, statusCode int, responseBody string) {
	t.Helper()
	proxyCtx := &goproxy.ProxyCtx{}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, sourceURL, nil)
	handler.PrepareRequest(req, proxyCtx)
	req = handleRequestAndClose(handler, req, proxyCtx)

	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(responseBody)),
	}
	handler.HandleResponse(resp, proxyCtx)

	replayedBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, responseBody, string(replayedBody))
	require.NoError(t, resp.Body.Close())
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
