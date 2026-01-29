package handlers

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dependabot/proxy/internal/config"
	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubAPIHandler_withUrlFallback(t *testing.T) {
	usingURL := config.Credentials{{
		"type":     "git_source",
		"url":      "https://github.com",
		"username": "x-access-token",
		"password": "super-secret-token",
	}}

	handler := NewGitHubAPIHandler(usingURL)

	req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "token", "super-secret-token", "valid api request")
}

func TestGitHubAPIHandler(t *testing.T) {
	installationCred := testGitSourceCred("github.com", "x-access-token", "v1.token")
	proximaCred := testGitSourceCred("github.com", "proxima-service-identity", "jwt")
	bitBucketCred := testGitSourceCred("bitbucket.com", "x-access-token", "other")
	rubygemsCred := config.Credential{
		"type":     "rubygems",
		"host":     "github.com",
		"username": "user",
		"password": "other",
	}

	tests := []struct {
		name                string
		personalAccessToken config.Credential
	}{
		{"legacy pat", testGitSourceCred("github.com", "x-access-token", "ghp_fakefakefakesuperfake")},
		{"fine grained pat", testGitSourceCred("github.com", "x-access-token", "github_pat_fakefakefakesuperfake")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentials := config.Credentials{
				tt.personalAccessToken,
				installationCred,
				proximaCred,
				bitBucketCred,
				rubygemsCred,
			}
			handler := NewGitHubAPIHandler(credentials)

			// Valid API request, prioritises non-installation token
			req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertHasTokenAuth(t, req, "token", tt.personalAccessToken.GetString("password"), "valid api request")

			// Valid API request with port, prioritises non-installation token
			req = httptest.NewRequest("GET", "https://api.github.com:443/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertHasTokenAuth(t, req, "token", tt.personalAccessToken.GetString("password"), "valid api request with port")

			// Different subdomain - not the GitHub API
			req = httptest.NewRequest("GET", "https://github.com/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertUnauthenticated(t, req, "different subdomain")

			// HTTP, not HTTPS
			req = httptest.NewRequest("GET", "http://api.github.com/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertUnauthenticated(t, req, "http, not https")
		})

		// With only the installation GitHub token
		credentials := config.Credentials{installationCred, bitBucketCred, rubygemsCred}
		handler := NewGitHubAPIHandler(credentials)

		// Valid API request, uses installation token
		req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
		req, _ = handler.HandleRequest(req, nil)
		assertHasTokenAuth(t, req, "token", installationCred.GetString("password"), "valid api request")

		// With only the proxima token
		credentials = config.Credentials{proximaCred, bitBucketCred, rubygemsCred}
		handler = NewGitHubAPIHandler(credentials)

		// Valid API request, uses installation token
		req = httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
		req, _ = handler.HandleRequest(req, nil)
		assertUnauthenticated(t, req, "Proxima is unauthenticated")
		assertHasProximaHeader(t, req, proximaCred.GetString("password"), "valid api request")
	}
}

func TestGitHubAPIHandler_AuthenticatedAccessToGitHubRepos(t *testing.T) {
	installationToken1 := "v1.token1"
	privateRepo1Cred := testGitSourceCred("github.com", "x-access-token", installationToken1, withAccessibleRepos([]string{"github/private-repo-1"}))
	allReposCred := testGitSourceCred("github.com", "x-access-token", installationToken1)

	installationToken2 := "v1.token2"
	privateRepo2Cred := testGitSourceCred("github.com", "x-access-token", installationToken2, withAccessibleRepos([]string{"github/private-repo-2"}))

	userToken := "ghp_fakefakefakesuperfake1"
	privateRepo3Cred := testGitSourceCred("github.com", "x-access-token", userToken, withAccessibleRepos([]string{"github/private-repo-3"}))

	tests := []struct {
		name               string
		repoNWO            string
		credentials        config.Credentials
		expectedCredential config.Credential
		isAuthenticated    bool
	}{
		{
			"no tokens for repo",
			"github/public-repo",
			config.Credentials{privateRepo1Cred, privateRepo3Cred},
			nil, // either token may be used, don't validate against a specific token
			true,
		},
		{
			"no installation tokens for repo",
			"github/private-repo-2",
			config.Credentials{privateRepo3Cred},
			nil,
			false,
		},
		{
			"installation token for repo",
			"github/private-repo-1",
			config.Credentials{privateRepo2Cred, privateRepo1Cred, privateRepo3Cred},
			nil, // either token may be used, don't validate against a specific token
			true,
		},
		{
			"all-repos installation token",
			"github/public-repo",
			config.Credentials{privateRepo2Cred, allReposCred, privateRepo3Cred},
			allReposCred,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewGitHubAPIHandler(tt.credentials)

			// Valid github git request, prioritises non-installation token
			req := httptest.NewRequest("GET", fmt.Sprintf("https://api.github.com/%s", tt.repoNWO), nil)
			req, _ = handler.HandleRequest(req, nil)

			if tt.expectedCredential != nil {
				assertHasTokenAuth(t, req, "token", tt.expectedCredential.GetString("password"), "valid api request")
			} else if tt.isAuthenticated {
				assertAuthenticated(t, req, "valid github request")
			} else {
				assertUnauthenticated(t, req, "valid github request")
			}
		})
	}
}

func TestGitHubAPIHandlerInProxima(t *testing.T) {
	installationCred := testGitSourceCred("foo.ghe.com", "x-access-token", "v1.token")
	bitBucketCred := testGitSourceCred("bitbucket.com", "x-access-token", "other")
	rubygemsCred := config.Credential{
		"type":     "rubygems",
		"host":     "foo.ghe.com",
		"username": "user",
		"password": "other",
	}

	tests := []struct {
		name                string
		personalAccessToken config.Credential
	}{
		{"legacy pat", testGitSourceCred("foo.ghe.com", "x-access-token", "ghp_fakefakefakesuperfake")},
		{"fine grained pat", testGitSourceCred("foo.ghe.com", "x-access-token", "github_pat_fakefakefakesuperfake")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentials := config.Credentials{
				tt.personalAccessToken,
				installationCred,
				bitBucketCred,
				rubygemsCred,
			}
			handler := NewGitHubAPIHandler(credentials)

			// Valid API request, prioritises non-installation token
			req := httptest.NewRequest("GET", "https://api.foo.ghe.com/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertHasTokenAuth(t, req, "token", tt.personalAccessToken.GetString("password"), "valid api request")

			// Valid API request with port, prioritises non-installation token
			req = httptest.NewRequest("GET", "https://api.foo.ghe.com:443/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertHasTokenAuth(t, req, "token", tt.personalAccessToken.GetString("password"), "valid api request with port")

			// Different subdomain - not the GitHub API
			req = httptest.NewRequest("GET", "https://ghe.com/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertUnauthenticated(t, req, "different subdomain")

			// HTTP, not HTTPS
			req = httptest.NewRequest("GET", "http://api.foo.ghe.com/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertUnauthenticated(t, req, "http, not https")
		})

		// With only the installation GitHub token
		credentials := config.Credentials{installationCred, bitBucketCred, rubygemsCred}
		handler := NewGitHubAPIHandler(credentials)

		// Valid API request, uses installation token
		req := httptest.NewRequest("GET", "https://api.foo.ghe.com/some-repo", nil)
		req, _ = handler.HandleRequest(req, nil)
		assertHasTokenAuth(t, req, "token", installationCred.GetString("password"), "valid api request")

	}
}

func TestGitHubAPIHandlerWithMulipleHosts(t *testing.T) {
	githubCred := testGitSourceCred("github.com", "x-access-token", "v1.token")
	fooGheCred := testGitSourceCred("foo.ghe.com", "x-access-token", "v1.token")

	tests := []struct {
		name                string
		personalAccessToken config.Credential
	}{
		{"legacy pat", testGitSourceCred("github.com", "x-access-token", "ghp_fakefakefakesuperfake")},
		{"fine grained pat", testGitSourceCred("github.com", "x-access-token", "github_pat_fakefakefakesuperfake")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentials := config.Credentials{
				tt.personalAccessToken,
				fooGheCred,
			}
			handler := NewGitHubAPIHandler(credentials)

			// Request to github.com, using the correct token
			req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertHasTokenAuth(t, req, "token", tt.personalAccessToken.GetString("password"), "request to github.com")

			// Request to foo.ghe.com, using the correct token
			req = httptest.NewRequest("GET", "https://api.foo.ghe.com/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertHasTokenAuth(t, req, "token", fooGheCred.GetString("password"), "request to foo.ghe.com")

			// Different subdomain - not the GitHub API
			req = httptest.NewRequest("GET", "https://github.com/some-repo", nil)
			req, _ = handler.HandleRequest(req, nil)
			assertUnauthenticated(t, req, "different subdomain")
		})
	}

	// With only the github.com token
	credentials := config.Credentials{githubCred}
	handler := NewGitHubAPIHandler(credentials)

	// Valid API request, uses only github.com token
	req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "token", githubCred.GetString("password"), "request to github.com")

	// With only the foo.ghe.com token
	fooGheCredentials := config.Credentials{fooGheCred}
	fooGhehandler := NewGitHubAPIHandler(fooGheCredentials)

	// Valid API request, uses only foo.ghe.com token
	fooGheReq := httptest.NewRequest("GET", "https://api.foo.ghe.com/some-repo", nil)
	fooGheReq, _ = fooGhehandler.HandleRequest(fooGheReq, nil)
	assertHasTokenAuth(t, fooGheReq, "token", fooGheCred.GetString("password"), "request to foo.ghe.com")
}

func TestGitHubAPIHandler_InstallationTokenFormat(t *testing.T) {
	installationCred := testGitSourceCred("github.com", "x-access-token", "ghs_fakefakefakesuperfake")
	credentials := config.Credentials{installationCred}
	handler := NewGitHubAPIHandler(credentials)

	req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "token", installationCred.GetString("password"), "valid api request")
}

func TestGitHubAPIHandler_InstallationTokenFormat_Proxima(t *testing.T) {
	installationCred := testGitSourceCred("foo.ghe.com", "x-access-token", "ghs_fakefakefakesuperfake")
	credentials := config.Credentials{installationCred}
	handler := NewGitHubAPIHandler(credentials)

	req := httptest.NewRequest("GET", "https://api.foo.ghe.com/some-repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasTokenAuth(t, req, "token", installationCred.GetString("password"), "valid api request")
}

func TestGitHubAPIHandler_TokenFallback(t *testing.T) {
	installationToken1 := "v1.token1"
	installationToken2 := "v1.token2"
	installationToken3 := "v1.token3"
	userToken1 := "ghp_fakefakefakesuperfake1"
	userToken2 := "ghp_fakefakefakesuperfake2"
	credentials := config.Credentials{
		testGitSourceCred("github.com", "x-access-token", installationToken1),
		testGitSourceCred("github.com", "x-access-token", installationToken2, withAccessibleRepos([]string{"foo/qux"})),
		testGitSourceCred("github.com", "x-access-token", installationToken3, withAccessibleRepos([]string{"foo/bar"})),
		testGitSourceCred("github.com", "x-access-token", userToken1),
		testGitSourceCred("github.com", "x-access-token", userToken2),
	}
	handler := NewGitHubAPIHandler(credentials)

	tests := []struct {
		name                   string
		authToken              string
		respCode               int
		url                    string
		expectRespCode         int
		expectTokens           []string
		expectReplacedResponse bool
	}{
		{
			"no valid tokens",
			"different token",
			404,
			"https://api.github.com/repos/github/dependabot-action",
			404,
			[]string{userToken1, userToken2, installationToken1},
			false,
		},
		{
			"first retry valid",
			userToken1,
			404,
			"https://api.github.com/repos/github/dependabot-action",
			200,
			[]string{userToken1},
			true,
		},
		{
			"second retry valid",
			userToken2,
			404,
			"https://api.github.com/repos/github/dependabot-action",
			200,
			[]string{userToken1, userToken2},
			true,
		},
		{
			"installation token valid",
			installationToken1,
			404,
			"https://api.github.com/repos/github/dependabot-action",
			200,
			[]string{userToken1, userToken2, installationToken1},
			true,
		},
		{
			"accessible repo",
			installationToken3,
			404,
			"https://api.github.com/repos/foo/bar",
			200,
			[]string{userToken1, userToken2, installationToken1, installationToken3},
			true,
		},
		{
			"retry not needed",
			"",
			200,
			"https://api.github.com/repos/github/dependabot-action",
			200,
			nil,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedTokens []string
			roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, c *goproxy.ProxyCtx) (*http.Response, error) {
				token := strings.TrimPrefix(r.Header.Get("Authorization"), "token ")
				capturedTokens = append(capturedTokens, token)
				if token == tt.authToken {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("world"))}, nil
				}
				return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("world"))}, nil
			})

			parsedUrl, _ := url.Parse(tt.url)
			req := &http.Request{Method: "GET", URL: parsedUrl, Header: http.Header{}}
			ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}
			rsp := &http.Response{StatusCode: tt.respCode, Body: io.NopCloser(strings.NewReader("hello"))}

			// tag request with auth so we'll handle retries
			_, _ = handler.HandleRequest(req, ctx)

			newRsp := handler.HandleResponse(rsp, ctx)
			assert.Equal(t, tt.expectRespCode, newRsp.StatusCode, "expected status code")
			assert.Equal(t, tt.expectTokens, capturedTokens, "attempted tokens")
			if tt.expectReplacedResponse {
				newRspBody, err := io.ReadAll(newRsp.Body)
				require.NoError(t, err, "reading newRspBody")
				assert.Equal(t, "world", string(newRspBody), "expected replaced response content")

				rspBody, err := io.ReadAll(rsp.Body)
				require.NoError(t, err, "reading rspBody")
				assert.Equal(t, "", string(rspBody), "original response should be drained")
			} else {
				newRspBody, err := io.ReadAll(newRsp.Body)
				require.NoError(t, err, "reading newRspBody")
				assert.Equal(t, "hello", string(newRspBody), "expected original response content")
			}
		})
	}
}

func TestGitHubAPIHandler_TokenFallback_In_Proxima(t *testing.T) {
	installationToken := "v1.token"
	userToken1 := "ghp_fakefakefakesuperfake1"
	userToken2 := "ghp_fakefakefakesuperfake2"
	credentials := config.Credentials{
		testGitSourceCred("foo.ghe.com", "x-access-token", installationToken),
		testGitSourceCred("foo.ghe.com", "x-access-token", userToken1),
		testGitSourceCred("foo.ghe.com", "x-access-token", userToken2),
	}
	handler := NewGitHubAPIHandler(credentials)
	url, err := url.Parse("https://api.foo.ghe.com/repos/github/dependabot-action")
	if err != nil {
		t.Errorf("parsing url: %v", err)
	}

	tests := []struct {
		name                   string
		authToken              string
		respCode               int
		expectRespCode         int
		expectTokens           []string
		expectReplacedResponse bool
	}{
		{
			"no valid tokens",
			"different token",
			404,
			404,
			[]string{userToken1, userToken2, installationToken},
			false,
		},
		{
			"first retry valid",
			userToken1,
			404,
			200,
			[]string{userToken1},
			true,
		},
		{
			"second retry valid",
			userToken2,
			404,
			200,
			[]string{userToken1, userToken2},
			true,
		},
		{
			"installation token valid",
			installationToken,
			404,
			200,
			[]string{userToken1, userToken2, installationToken},
			true,
		},
		{
			"retry not needed",
			"",
			200,
			200,
			nil,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedTokens []string
			roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, c *goproxy.ProxyCtx) (*http.Response, error) {
				token := strings.TrimPrefix(r.Header.Get("Authorization"), "token ")
				capturedTokens = append(capturedTokens, token)
				if token == tt.authToken {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("world"))}, nil
				}
				return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("world"))}, nil
			})

			req := &http.Request{Method: "GET", URL: url, Header: http.Header{}}
			ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}
			rsp := &http.Response{StatusCode: tt.respCode, Body: io.NopCloser(strings.NewReader("hello"))}

			// tag request with auth so we'll handle retries
			_, _ = handler.HandleRequest(req, ctx)

			newRsp := handler.HandleResponse(rsp, ctx)
			assert.Equal(t, tt.expectRespCode, newRsp.StatusCode, "expected status code")
			assert.Equal(t, tt.expectTokens, capturedTokens, "attempted tokens")
			if tt.expectReplacedResponse {
				newRspBody, err := io.ReadAll(newRsp.Body)
				require.NoError(t, err, "reading newRspBody")
				assert.Equal(t, "world", string(newRspBody), "expected replaced response content")

				rspBody, err := io.ReadAll(rsp.Body)
				require.NoError(t, err, "reading rspBody")
				assert.Equal(t, "", string(rspBody), "original response should be drained")
			} else {
				newRspBody, err := io.ReadAll(newRsp.Body)
				require.NoError(t, err, "reading newRspBody")
				assert.Equal(t, "hello", string(newRspBody), "expected original response content")
			}
		})
	}
}
