package handlers

import (
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
	"github.com/dependabot/proxy/internal/ctxdata"
)

func TestGitServerHandler_url(t *testing.T) {
	cred := map[string]interface{}{
		"type":     "git_source",
		"url":      "https://github.com",
		"username": "x-access-token",
		"password": "token",
	}

	handler := NewGitServerHandler(config.Credentials{cred}, nil)

	// Valid github git request, prioritises non-installation token
	req := httptest.NewRequest("GET", "https://github.com/account/repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req,
		cred["username"].(string),
		cred["password"].(string),
		"valid github request")
}

func TestGitServerHandler(t *testing.T) {
	installationCred := testGitSourceCred("github.com", "x-access-token", "v1.token")
	otherGitHubCred := testGitSourceCred("github.com", "x-access-token", "oauth-token")
	bitBucketCred := testGitSourceCred("bitbucket.org", "x-access-token", "other")
	gheCred := testGitSourceCred("ghe.some-corp.com", "x-access-token", "corp")
	proximaCred := testGitSourceCred("github.com", "proxima-service-identity", "jwt")

	rubygemsCred := map[string]interface{}{
		"type":     "rubygems",
		"host":     "github.com",
		"username": "user",
		"password": "other",
	}

	credentials := config.Credentials{
		otherGitHubCred,
		installationCred,
		bitBucketCred,
		gheCred,
		rubygemsCred,
		proximaCred,
	}
	handler := NewGitServerHandler(credentials, nil)

	// Valid github git request, prioritises non-installation token
	req := httptest.NewRequest("GET", "https://github.com/account/repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req,
		otherGitHubCred.GetString("username"),
		otherGitHubCred.GetString("password"),
		"valid github request")

	// Valid github git request, git user included but no password
	req = httptest.NewRequest("GET", "https://git@github.com/account/repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req,
		otherGitHubCred.GetString("username"),
		otherGitHubCred.GetString("password"),
		"valid github request")

	// Valid bitbucket git request, prioritises non-installation token
	req = httptest.NewRequest("GET", "https://bitbucket.org:443/account/repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req,
		bitBucketCred.GetString("username"),
		bitBucketCred.GetString("password"),
		"valid bitbucket request")

	// Valid GHE request
	req = httptest.NewRequest("GET", "https://ghe.some-corp.com/account/_dependabot", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req,
		gheCred.GetString("username"),
		gheCred.GetString("password"),
		"valid ghe request")

	// Special GHE dependabot-api endpoint
	req = httptest.NewRequest("GET", "https://ghe.some-corp.com/_dependabot/update_jobs/123/details", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "_dependabot api URL prefix")

	// Different subdomain - not the GitHub API
	req = httptest.NewRequest("GET", "https://api.github.com/account/repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequest("GET", "http://github.com/account/repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertUnauthenticated(t, req, "http, not https")

	credentials = config.Credentials{
		installationCred,
		bitBucketCred,
		rubygemsCred,
	}
	handler = NewGitServerHandler(credentials, nil)

	// Valid github git request, uses installation token
	req = httptest.NewRequest("GET", "https://github.com/account/repo", nil)
	req, _ = handler.HandleRequest(req, nil)
	assertHasBasicAuth(t, req,
		installationCred.GetString("username"),
		installationCred.GetString("password"),
		"valid github request")
}

func TestGitServerHandler_AuthenticatedAccessToGitHubRepos(t *testing.T) {
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
			handler := NewGitServerHandler(tt.credentials, nil)

			// Valid github git request, prioritises non-installation token
			req := httptest.NewRequest("GET", fmt.Sprintf("https://github.com/%s", tt.repoNWO), nil)
			req, _ = handler.HandleRequest(req, nil)

			if tt.expectedCredential != nil {
				assertHasBasicAuth(t, req,
					tt.expectedCredential.GetString("username"),
					tt.expectedCredential.GetString("password"),
					"valid github request")
			} else if tt.isAuthenticated {
				assertAuthenticated(t, req, "valid github request")
			} else {
				assertUnauthenticated(t, req, "valid github request")
			}
		})
	}
}

func TestGitServerHandler404Retry(t *testing.T) {
	installationCred := testGitSourceCred("github.com", "x-access-token", "v1.token")
	credentials := config.Credentials{installationCred}
	handler := NewGitServerHandler(credentials, nil)
	rsp := &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}
	url, err := url.Parse("https://example.com")
	if err != nil {
		t.Errorf("parsing url: %v", err)
	}

	roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
		assert.Equal(t, "", r.Header.Get("Authorization"), "auth should be removed")
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	req := &http.Request{Method: "GET", URL: url, Header: http.Header{}}
	req.SetBasicAuth("user", "pass")
	ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}

	newRsp := handler.HandleResponse(rsp, ctx)
	assert.Equal(t, 404, newRsp.StatusCode, "no retry without addedAuthCtxKey")

	ctxdata.SetValue(ctx, addedAuthCtxKey, &gitCredentials{username: "x-access-token", password: "v1.token"})
	newRsp = handler.HandleResponse(rsp, ctx)
	assert.Equal(t, 401, newRsp.StatusCode, "should retry")
}

func TestGitServerHandlerNoRetry(t *testing.T) {
	installationCred := testGitSourceCred("ghes.com", "x-access-token", "v1.token")
	credentials := config.Credentials{installationCred}
	handler := NewGitServerHandler(credentials, nil)
	rsp := &http.Response{StatusCode: 404}
	url := "https://ghes.com/api/v3"

	roundTripper := goproxy.RoundTripperFunc(func(*http.Request, *goproxy.ProxyCtx) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	req := httptest.NewRequest("GET", url, nil)
	req.SetBasicAuth("x-access-token", "v1.token")
	ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}

	newRsp := handler.HandleResponse(rsp, ctx)
	assert.Equal(t, 404, newRsp.StatusCode, "")

	// Ensure we _don't_ retry
	ctxdata.SetValue(ctx, addedAuthCtxKey, &gitCredentials{username: "x-access-token", password: "v1.token"})
	newRsp = handler.HandleResponse(rsp, ctx)
	assert.Equal(t, 404, newRsp.StatusCode, "")
}

func TestGitServerHandler_TokenFallback(t *testing.T) {
	installationToken := "v1.token"
	userToken1 := "ghp_fakefakefakesuperfake1"
	userToken2 := "ghp_fakefakefakesuperfake2"
	credentials := config.Credentials{
		testGitSourceCred("github.com", "x-access-token", installationToken),
		testGitSourceCred("github.com", "x-access-token", userToken1),
		testGitSourceCred("github.com", "x-access-token", userToken2),
		testGitSourceCred("github.com", "proxima-service-identity", "jwt"),
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
			401,
			401,
			[]string{userToken2, installationToken},
			false,
		},
		{
			"no valid tokens and unauthed retry",
			"different token",
			404,
			401,
			[]string{userToken2, installationToken, ""},
			true,
		},
		{
			"first retry valid so we don't retry again",
			userToken2,
			404,
			200,
			[]string{userToken2},
			true,
		},
		{
			"second retry valid",
			installationToken,
			404,
			200,
			[]string{userToken2, installationToken},
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
			handler := NewGitServerHandler(credentials, nil)

			var capturedTokens []string
			roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, c *goproxy.ProxyCtx) (*http.Response, error) {
				_, token, _ := r.BasicAuth()
				capturedTokens = append(capturedTokens, token)
				if token == tt.authToken {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("world"))}, nil
				}
				return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("world"))}, nil
			})

			req, err := http.NewRequest("GET", "https://github.com/github/dependabot-action/info/refs?service=git-upload-pack", nil)
			require.NoError(t, err, "failed to create request")
			ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}
			rsp := &http.Response{StatusCode: tt.respCode, Body: io.NopCloser(strings.NewReader("hello"))}

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

func TestGitServerHandler_TokenFallbackWithPost(t *testing.T) {
	installationToken := "v1.token"
	userToken := "ghp_fakefakefakesuperfake"
	credentials := config.Credentials{
		testGitSourceCred("github.com", "x-access-token", installationToken),
		testGitSourceCred("github.com", "x-access-token", userToken),
	}
	handler := NewGitServerHandler(credentials, nil)

	tests := []struct {
		name           string
		authToken      string
		url            string
		respCode       int
		expectRespCode int
		expectTokens   []string
	}{
		// test POST for different path doesn't retry
		// test POST with 1 credential doesn't copy body
		{
			"retries with post for git-upload-pack",
			installationToken,
			"https://github.com/github/dependabot-action/git-upload-pack",
			404,
			200,
			[]string{userToken, installationToken},
		},
		{
			"retry not needed",
			"",
			"https://github.com/github/dependabot-action/git-upload-pack",
			200,
			200,
			[]string{userToken},
		},
		{
			"doesn't retry for unsupported post path",
			installationToken,
			"https://github.com/github/dependabot-action",
			404,
			404,
			[]string{userToken},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedTokens []string
			roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, c *goproxy.ProxyCtx) (*http.Response, error) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err, "failed to read req body")
				assert.Equal(t, "test body", string(body), "request body mismatch")

				_, token, _ := r.BasicAuth()
				capturedTokens = append(capturedTokens, token)

				if token == tt.authToken {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
				}
				return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(""))}, nil
			})

			req, err := http.NewRequest("POST", tt.url, io.NopCloser(strings.NewReader("test body")))
			require.NoError(t, err, "failed to create request")
			ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}
			rsp := &http.Response{StatusCode: tt.respCode, Body: io.NopCloser(strings.NewReader(""))}

			req, _ = handler.HandleRequest(req, ctx)
			// trigger cloning body
			_, err = roundTripper(req, ctx)
			require.NoError(t, err, "first request err")
			newRsp := handler.HandleResponse(rsp, ctx)
			assert.Equal(t, tt.expectRespCode, newRsp.StatusCode, "expected status code")
			assert.Equal(t, tt.expectTokens, capturedTokens, "attempted tokens")
		})
	}
}

func TestGitServerHandler_NoCloneWithSingleCredPost(t *testing.T) {
	installationToken := "v1.token"
	credentials := config.Credentials{
		testGitSourceCred("github.com", "x-access-token", installationToken),
	}
	handler := NewGitServerHandler(credentials, nil)

	req, err := http.NewRequest("POST", "https://github.com/github/dependabot-action/git-upload-pack", io.NopCloser(strings.NewReader("test body")))
	require.NoError(t, err, "failed to create request")
	ctx := &goproxy.ProxyCtx{Req: req}
	_, _ = handler.HandleRequest(req, ctx)
	_, found := ctxdata.GetBuffer(ctx, reqBodyCtxKey)

	assert.False(t, found, "expect clone buffer not present")
}

func TestGitServerHandler_RepositoryScopedCredentials(t *testing.T) {
	scopedInstallationCredAccount1 := testGitSourceCred("github.com", "x-access-token", "v1.token1", withAccessibleRepos([]string{"account1/repo1"}))
	scopedInstallationCredAccount2 := testGitSourceCred("github.com", "x-access-token", "v1.token2", withAccessibleRepos([]string{"account1/repo1", "account1/repo2"}))
	scopedInstallationCredAccount3 := testGitSourceCred("github.com", "x-access-token", "v1.token3", withAccessibleRepos([]string{"account2/repo3"}))
	unscopedInstallationCred := testGitSourceCred("github.com", "x-access-token", "v1.token4")
	otherGitHubCred := testGitSourceCred("github.com", "x-access-token", "oauth-token")
	bitBucketCred := testGitSourceCred("bitbucket.org", "x-access-token", "other")

	credentials := config.Credentials{
		scopedInstallationCredAccount1,
		scopedInstallationCredAccount2,
		scopedInstallationCredAccount3,
		unscopedInstallationCred,
		otherGitHubCred,
		bitBucketCred,
	}
	handler := NewGitServerHandler(credentials, nil)

	tests := map[string]string{
		"valid github git request":         "https://github.com/account1/repo1",
		"case insensitive repository name": "http://github.com/Account1/repo1",
	}

	for name, url := range tests {
		t.Run(name, func(t *testing.T) {
			var capturedTokens []string
			roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, c *goproxy.ProxyCtx) (*http.Response, error) {
				_, token, _ := r.BasicAuth()
				capturedTokens = append(capturedTokens, token)
				return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(""))}, nil
			})

			req := httptest.NewRequest("GET", url, nil)
			ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}
			rsp := &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(""))}

			handler.HandleResponse(rsp, ctx)
			assert.Equal(t, []string{
				otherGitHubCred.GetString("password"),
				unscopedInstallationCred.GetString("password"),
				scopedInstallationCredAccount1.GetString("password"),
				scopedInstallationCredAccount2.GetString("password"),
			}, capturedTokens)
		})
	}
}

type TestScopeRequester struct {
	receivedRequest bool
}

const jitToken = "newToken"

func (t *TestScopeRequester) RequestJITAccess(ctx *goproxy.ProxyCtx, endpoint string, account string, repo string) (*config.Credential, error) {
	t.receivedRequest = true

	return &config.Credential{
		"username": "x-access-token",
		"password": jitToken,
	}, nil
}

func TestGitServerHandler_RequestJITAccess(t *testing.T) {
	urlsThatRequestMoreScope := []struct {
		url               string
		jitAccessEndpoint string
	}{
		{url: "https://github.com/will/request", jitAccessEndpoint: "jit-access"},
		{url: "https://github.com:443/will/request", jitAccessEndpoint: "jit-access"},
		{url: "https://github.com:443/will/request/info/refs?service=git-upload-pack", jitAccessEndpoint: "jit-access"},
		{url: "https://github.com/wont/request", jitAccessEndpoint: ""},
		{url: "https://github.com/also-wont/request", jitAccessEndpoint: ""},
	}

	for _, test := range urlsThatRequestMoreScope {
		t.Run("with URL "+test.url, func(t *testing.T) {
			jitCred := testJITAccessCred("git_source", "github.com", test.jitAccessEndpoint)
			credentials := config.Credentials{jitCred}

			testClient := &TestScopeRequester{}
			handler := NewGitServerHandler(credentials, testClient)
			rsp := &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}
			url, err := url.Parse(test.url)
			if err != nil {
				t.Errorf("parsing url: %v", err)
			}

			roundTripper := goproxy.RoundTripperFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
				_, pass, ok := r.BasicAuth()
				if !ok {
					return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(""))}, nil
				}
				if pass != jitToken {
					return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(""))}, nil
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
			})
			req := &http.Request{Method: "GET", URL: url, Header: http.Header{}}
			req.SetBasicAuth("user", "pass")
			ctx := &goproxy.ProxyCtx{Req: req, RoundTripper: roundTripper}

			ctxdata.SetValue(ctx, addedAuthCtxKey, &gitCredentials{username: "x-access-token", password: "v1.token"})
			newRsp := handler.HandleResponse(rsp, ctx)
			assert.Equal(t, test.jitAccessEndpoint != "", testClient.receivedRequest, "request more scope unexpected")
			if test.jitAccessEndpoint != "" {
				assert.Equal(t, 200, newRsp.StatusCode, "should have succeeded")
			} else {
				assert.Equal(t, 401, newRsp.StatusCode, "should retry")
			}
		})
	}
}
