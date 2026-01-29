package handlers

import (
	"bytes"
	"fmt"
	"log"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dependabot/proxy/internal/config"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
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
	if err != nil {
		t.Errorf("constructing httpmock responser: %v", err)
	}
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
	if err != nil {
		t.Errorf("constructing httpmock responser: %v", err)
	}
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
	if err != nil {
		t.Errorf("constructing httpmock responser: %v", err)
	}
	httpmock.RegisterResponder("GET", "https://pkgs.dev.azure.com/example/public/_packaging/some-feed2/nuget/v3/index.json", azureDevOpsJsonResponder2)

	// Log for initial authentication contains appropriate information
	var buf bytes.Buffer
	log.SetOutput(&buf)
	handler := NewNugetFeedHandler(credentials)
	logContents := buf.String()
	assert.False(t, strings.Contains(logContents, "* authenticating nuget feed request (host: api.nuget.org, bearer auth)"), "don't authenticate a feed without a token or password")
	assert.True(t, strings.Contains(logContents, "unauthorized for nuget feed https://nuget.example.com/auth-required/v3"), "authentication failure is reported")

	req := httptest.NewRequest("GET", "https://corp.dependabot.com/nuget", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "dependabot feed request")

	req = httptest.NewRequest("GET", "https://corp.deltaforce.com/somepkg", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce feed request")

	// Base URL listed in the v3 feed index
	req = httptest.NewRequest("GET", "https://pkg-search.dependabot.com/query", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "url listed in feed index")

	// Other URL listed in the v3 feed index
	req = httptest.NewRequest("GET", "https://pkg-search.dependabot.com/autocomplete", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "other url in feed index")

	// Template URL not authenticated
	req = httptest.NewRequest("GET", "https://pkg-search.dependabot.com/some.package/1.2.3/ReportAbuse", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "Template URL")

	// v2 API
	req = httptest.NewRequest("GET", "https://nuget.example.com/v2/FindPackagesById()?Id='Some.Package'", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "authenticated v2 API")

	// v2 API - redirected
	req = httptest.NewRequest("GET", "https://redirected.example.com/v2/FindPackagesById()?Id='Some.Package'", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "redirected authenticated v2 API")

	// Path mismatch
	req = httptest.NewRequest("GET", "https://corp.dependabot.com/foo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "Path mismatch")

	// Missing repo subdomain
	req = httptest.NewRequest("GET", "https://dependabot.com/nuget", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://corp.dependabot.com/nuget", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "Bearer", dependabotToken, "dependabot feed http request")

	// HTTP, not HTTPS, path mismatch
	req = httptest.NewRequest("GET", "http://corp.dependabot.com/feed", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "Path mismatch")

	// Not a GET request
	req = httptest.NewRequest("POST", "https://corp.dependabot.com/nuget", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "post request")

	// Azure DevOps
	req = httptest.NewRequest("GET", "https://pkgs.dev.azure.com/dependabot/_packaging/dependabot/nuget/v3/index.json", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "Azure DevOps feed request")

	// Azure DevOps case insensitive
	req = httptest.NewRequest("GET", "https://PKGS.dev.azure.com/dependabot/_packaging/dependabot/nuget/v3/index.json", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "Azure DevOps case insensitive feed request")

	// Reset buffer to catch log contents
	buf.Reset()
	req = httptest.NewRequest("GET", "https://pkgs.dev.azure.com/example/public/_packaging/some-feed/nuget/v3/some.package/index.json", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req, "", dependabotToken, "Azure DevOps token handling")
	logContents = buf.String()
	assert.True(t, strings.Contains(logContents, ", basic auth for Azure DevOps)"), "expected Azure DevOps token handling")

	// Check Azure token edge case in which it has a prepended ":" and is treated as a password successfully
	req = httptest.NewRequest("GET", "https://pkgs.dev.azure.com/example/public/_packaging/some-feed2/nuget/v3/some.package/index.json", nil)
	req, _ = handler.HandleRequest(req, nil)
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
	log.SetOutput(&buf)
	NewNugetFeedHandler(credentials)
	logContents := buf.String()

	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/packages"), "include PackageBaseAddress")
	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/query"), "include SearchQueryService")
	assert.True(t, strings.Contains(logContents, "  added url to authentication list: https://nuget.example.com/v3/unknown"), "include SomeUnknownServiceTypeButShouldStillBeIncluded")
}
