package handlers

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/config"
)

func TestGitHubAPIHandler_withUrlFallback(t *testing.T) {
	usingURL := config.Credentials{{
		"type":     "git_source",
		"url":      "https://github.com",
		"username": "x-access-token",
		"password": "super-secret-token",
	}}

	handler := NewGitHubAPIHandler(usingURL, nil)

	req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
	req = handleRequestAndClose(handler, req, nil)
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
			handler := NewGitHubAPIHandler(credentials, nil)

			// Valid API request, prioritises non-installation token
			req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertHasTokenAuth(t, req, "token", tt.personalAccessToken.GetString("password"), "valid api request")

			// Valid API request with port, prioritises non-installation token
			req = httptest.NewRequest("GET", "https://api.github.com:443/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertHasTokenAuth(t, req, "token", tt.personalAccessToken.GetString("password"), "valid api request with port")

			// Different subdomain - not the GitHub API
			req = httptest.NewRequest("GET", "https://github.com/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertUnauthenticated(t, req, "different subdomain")

			// HTTP, not HTTPS
			req = httptest.NewRequest("GET", "http://api.github.com/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertUnauthenticated(t, req, "http, not https")
		})

		// With only the installation GitHub token
		credentials := config.Credentials{installationCred, bitBucketCred, rubygemsCred}
		handler := NewGitHubAPIHandler(credentials, nil)

		// Valid API request, uses installation token
		req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
		req = handleRequestAndClose(handler, req, nil)
		assertHasTokenAuth(t, req, "token", installationCred.GetString("password"), "valid api request")

		// With only the proxima token
		credentials = config.Credentials{proximaCred, bitBucketCred, rubygemsCred}
		handler = NewGitHubAPIHandler(credentials, nil)

		// Valid API request, uses installation token
		req = httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
		req = handleRequestAndClose(handler, req, nil)
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

	userToken := "ghp_fakefakefakesuperfake1" //nolint:gosec // test credential
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
			handler := NewGitHubAPIHandler(tt.credentials, nil)

			// Valid github git request, prioritises non-installation token
			req := httptest.NewRequest("GET", fmt.Sprintf("https://api.github.com/%s", tt.repoNWO), nil)
			req = handleRequestAndClose(handler, req, nil)

			switch {
			case tt.expectedCredential != nil:
				assertHasTokenAuth(t, req, "token", tt.expectedCredential.GetString("password"), "valid api request")
			case tt.isAuthenticated:
				assertAuthenticated(t, req, "valid github request")
			default:
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
			handler := NewGitHubAPIHandler(credentials, nil)

			// Valid API request, prioritises non-installation token
			req := httptest.NewRequest("GET", "https://api.foo.ghe.com/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertHasTokenAuth(t, req, "token", tt.personalAccessToken.GetString("password"), "valid api request")

			// Valid API request with port, prioritises non-installation token
			req = httptest.NewRequest("GET", "https://api.foo.ghe.com:443/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertHasTokenAuth(t, req, "token", tt.personalAccessToken.GetString("password"), "valid api request with port")

			// Different subdomain - not the GitHub API
			req = httptest.NewRequest("GET", "https://ghe.com/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertUnauthenticated(t, req, "different subdomain")

			// HTTP, not HTTPS
			req = httptest.NewRequest("GET", "http://api.foo.ghe.com/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertUnauthenticated(t, req, "http, not https")
		})

		// With only the installation GitHub token
		credentials := config.Credentials{installationCred, bitBucketCred, rubygemsCred}
		handler := NewGitHubAPIHandler(credentials, nil)

		// Valid API request, uses installation token
		req := httptest.NewRequest("GET", "https://api.foo.ghe.com/some-repo", nil)
		req = handleRequestAndClose(handler, req, nil)
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
			handler := NewGitHubAPIHandler(credentials, nil)

			// Request to github.com, using the correct token
			req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertHasTokenAuth(t, req, "token", tt.personalAccessToken.GetString("password"), "request to github.com")

			// Request to foo.ghe.com, using the correct token
			req = httptest.NewRequest("GET", "https://api.foo.ghe.com/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertHasTokenAuth(t, req, "token", fooGheCred.GetString("password"), "request to foo.ghe.com")

			// Different subdomain - not the GitHub API
			req = httptest.NewRequest("GET", "https://github.com/some-repo", nil)
			req = handleRequestAndClose(handler, req, nil)
			assertUnauthenticated(t, req, "different subdomain")
		})
	}

	// With only the github.com token
	credentials := config.Credentials{githubCred}
	handler := NewGitHubAPIHandler(credentials, nil)

	// Valid API request, uses only github.com token
	req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "token", githubCred.GetString("password"), "request to github.com")

	// With only the foo.ghe.com token
	fooGheCredentials := config.Credentials{fooGheCred}
	fooGhehandler := NewGitHubAPIHandler(fooGheCredentials, nil)

	// Valid API request, uses only foo.ghe.com token
	fooGheReq := httptest.NewRequest("GET", "https://api.foo.ghe.com/some-repo", nil)
	fooGheReq = handleRequestAndClose(fooGhehandler, fooGheReq, nil)
	assertHasTokenAuth(t, fooGheReq, "token", fooGheCred.GetString("password"), "request to foo.ghe.com")
}

func TestGitHubAPIHandler_InstallationTokenFormat(t *testing.T) {
	installationCred := testGitSourceCred("github.com", "x-access-token", "ghs_fakefakefakesuperfake")
	credentials := config.Credentials{installationCred}
	handler := NewGitHubAPIHandler(credentials, nil)

	req := httptest.NewRequest("GET", "https://api.github.com/some-repo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "token", installationCred.GetString("password"), "valid api request")
}

func TestGitHubAPIHandler_InstallationTokenFormat_Proxima(t *testing.T) {
	installationCred := testGitSourceCred("foo.ghe.com", "x-access-token", "ghs_fakefakefakesuperfake")
	credentials := config.Credentials{installationCred}
	handler := NewGitHubAPIHandler(credentials, nil)

	req := httptest.NewRequest("GET", "https://api.foo.ghe.com/some-repo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasTokenAuth(t, req, "token", installationCred.GetString("password"), "valid api request")
}

func TestGitHubAPIHandler_TokenFallback(t *testing.T) {
	installationToken1 := "v1.token1"
	installationToken2 := "v1.token2"
	installationToken3 := "v1.token3"
	userToken1 := "ghp_fakefakefakesuperfake1" //nolint:gosec // test credential
	userToken2 := "ghp_fakefakefakesuperfake2" //nolint:gosec // test credential
	credentials := config.Credentials{
		testGitSourceCred("github.com", "x-access-token", installationToken1),
		testGitSourceCred("github.com", "x-access-token", installationToken2, withAccessibleRepos([]string{"foo/qux"})),
		testGitSourceCred("github.com", "x-access-token", installationToken3, withAccessibleRepos([]string{"foo/bar"})),
		testGitSourceCred("github.com", "x-access-token", userToken1),
		testGitSourceCred("github.com", "x-access-token", userToken2),
	}

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
			handler := NewGitHubAPIHandler(credentials, nil)
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
			_ = handleRequestAndClose(handler, req, ctx)

			newRsp := handler.HandleResponse(rsp, ctx)
			defer newRsp.Body.Close()
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
	userToken1 := "ghp_fakefakefakesuperfake1" //nolint:gosec // test credential
	userToken2 := "ghp_fakefakefakesuperfake2" //nolint:gosec // test credential
	credentials := config.Credentials{
		testGitSourceCred("foo.ghe.com", "x-access-token", installationToken),
		testGitSourceCred("foo.ghe.com", "x-access-token", userToken1),
		testGitSourceCred("foo.ghe.com", "x-access-token", userToken2),
	}
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
			handler := NewGitHubAPIHandler(credentials, nil)
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
			_ = handleRequestAndClose(handler, req, ctx)

			newRsp := handler.HandleResponse(rsp, ctx)
			defer newRsp.Body.Close()
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

type testGitHubAPIScopeRequester struct {
	callCount int
	result    *config.Credential
	err       error
}

func (t *testGitHubAPIScopeRequester) RequestJITAccess(ctx *goproxy.ProxyCtx, endpoint string, username string, password string, account string, repo string) (*config.Credential, error) {
	t.callCount++
	return t.result, t.err
}

func TestGitHubAPIHandler_JITAccessFallback(t *testing.T) {
	staticToken := "ghp_static"
	jitToken := "ghp_jit"
	credentials := config.Credentials{
		testGitSourceCred("github.com", "x-access-token", staticToken),
		{
			"type":            "jit_access",
			"credential-type": "git_source",
			"host":            "github.com",
			"endpoint":        "https://dependabot.example.com/jit_access",
		},
	}
	requester := &testGitHubAPIScopeRequester{
		result: &config.Credential{
			"username": "x-access-token",
			"password": jitToken,
		},
	}
	handler := NewGitHubAPIHandler(credentials, requester)

	var capturedTokens []string
	roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, c *goproxy.ProxyCtx) (*http.Response, error) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "token ")
		capturedTokens = append(capturedTokens, token)
		if token == jitToken {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("jit-ok"))}, nil
		}
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("not found"))}, nil
	})

	req := httptest.NewRequest("GET", "https://api.github.com:443/repos/example/internal-repo/releases?per_page=100", nil)
	ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}
	rsp := &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("initial"))}

	_ = handleRequestAndClose(handler, req, ctx)
	newRsp := handler.HandleResponse(rsp, ctx)
	defer newRsp.Body.Close()

	body, err := io.ReadAll(newRsp.Body)
	require.NoError(t, err)
	assert.Equal(t, 200, newRsp.StatusCode)
	assert.Equal(t, "jit-ok", string(body))
	assert.Equal(t, []string{staticToken, jitToken}, capturedTokens)
	assert.Equal(t, 1, requester.callCount)
}

func TestGitHubAPIHandler_DoesNotFallbackWithoutStaticCredentials(t *testing.T) {
	credentials := config.Credentials{
		{
			"type":            "jit_access",
			"credential-type": "git_source",
			"host":            "github.com",
			"endpoint":        "https://dependabot.example.com/jit_access",
		},
	}
	requester := &testGitHubAPIScopeRequester{}
	handler := NewGitHubAPIHandler(credentials, requester)

	roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, c *goproxy.ProxyCtx) (*http.Response, error) {
		t.Fatal("request without proxy-added auth should not be retried")
		return nil, nil
	})
	req := httptest.NewRequest("GET", "https://api.github.com/repos/example/internal-repo/releases", nil)
	ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}
	rsp := &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("initial"))}

	_ = handleRequestAndClose(handler, req, ctx)
	newRsp := handler.HandleResponse(rsp, ctx)
	defer newRsp.Body.Close()

	assert.Equal(t, 404, newRsp.StatusCode)
	assert.Equal(t, 0, requester.callCount)
}

func TestGitHubAPIHandler_FailedJITAccessIsNotRetriedForRepository(t *testing.T) {
	credentials := config.Credentials{
		testGitSourceCred("github.com", "x-access-token", "ghp_static"),
		{
			"type":            "jit_access",
			"credential-type": "git_source",
			"host":            "github.com",
			"endpoint":        "https://dependabot.example.com/jit_access",
		},
	}
	requester := &testGitHubAPIScopeRequester{err: errors.New("JIT access unavailable")}
	handler := NewGitHubAPIHandler(credentials, requester)
	roundTripCount := 0
	roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, c *goproxy.ProxyCtx) (*http.Response, error) {
		roundTripCount++
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("not found"))}, nil
	})

	for range 2 {
		req := httptest.NewRequest("GET", "https://api.github.com/repos/example/internal-repo/releases", nil)
		ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}
		rsp := &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("initial"))}
		_ = handleRequestAndClose(handler, req, ctx)
		newRsp := handler.HandleResponse(rsp, ctx)
		newRsp.Body.Close()
	}

	assert.Equal(t, 1, requester.callCount)
	assert.Equal(t, 1, roundTripCount)
}

func TestGitHubAPIHandler_JITAccessTokenIsCached(t *testing.T) {
	staticToken := "ghp_static"
	jitToken := "ghp_jit"
	credentials := config.Credentials{
		testGitSourceCred("github.com", "x-access-token", staticToken),
		{
			"type":            "jit_access",
			"credential-type": "git_source",
			"host":            "github.com",
			"endpoint":        "https://dependabot.example.com/jit_access",
		},
	}
	requester := &testGitHubAPIScopeRequester{
		result: &config.Credential{
			"username": "x-access-token",
			"password": jitToken,
		},
	}
	handler := NewGitHubAPIHandler(credentials, requester)

	roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, c *goproxy.ProxyCtx) (*http.Response, error) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "token ")
		if token == jitToken {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("jit-ok"))}, nil
		}
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("denied"))}, nil
	})

	req1 := httptest.NewRequest("GET", "https://api.github.com/repos/dependabot/proxy", nil)
	ctx1 := &goproxy.ProxyCtx{Req: req1, RoundTripper: roundTripper}
	rsp1 := &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("initial"))}
	_ = handleRequestAndClose(handler, req1, ctx1)
	newRsp1 := handler.HandleResponse(rsp1, ctx1)
	defer newRsp1.Body.Close()
	assert.Equal(t, 200, newRsp1.StatusCode)
	assert.Equal(t, 1, requester.callCount)

	req2 := httptest.NewRequest("GET", "https://api.github.com/repos/dependabot/proxy", nil)
	ctx2 := &goproxy.ProxyCtx{Req: req2, RoundTripper: roundTripper}
	rsp2 := &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("initial"))}
	_ = handleRequestAndClose(handler, req2, ctx2)
	newRsp2 := handler.HandleResponse(rsp2, ctx2)
	defer newRsp2.Body.Close()
	assert.Equal(t, 200, newRsp2.StatusCode)

	// Cached repo-scoped credentials should be retried before requesting JIT again.
	assert.Equal(t, 1, requester.callCount)
}
