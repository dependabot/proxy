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
)

func TestPythonIndexHandler(t *testing.T) {
	dependabotToken := "123"                  //nolint:gosec // test credential
	dependabotSecToken := "dependabot:sec123" //nolint:gosec // test credential
	simpleSecToken := "simple:sec245"
	deltaForceUser := "some-user"
	deltaForcePassword := "456"
	credentials := config.Credentials{
		config.Credential{
			"type":      "python_index",
			"index-url": "https://corp.dependabot.com/pyreg/",
			"token":     dependabotToken,
		},
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pypy.com/dependabot/+simple/",
			"token":     dependabotSecToken,
		},
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pypy.com/simple/simple/",
			"token":     simpleSecToken,
		},
		config.Credential{
			"type":      "python_index",
			"index-url": "https://corp.deltaforce.com:443/",
			"token":     fmt.Sprintf("%s:%s", deltaForceUser, deltaForcePassword),
		},
		config.Credential{
			"type":     "python_index",
			"host":     "pkgs.dev.azure.com",
			"username": deltaForceUser,
			"password": deltaForcePassword,
		},
		config.Credential{
			"type":  "python_index",
			"url":   "https://example.com:443/",
			"token": fmt.Sprintf("%s:%s", deltaForceUser, deltaForcePassword),
		},
	}
	handler := NewPythonIndexHandler(credentials)

	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.dependabot.com/pyreg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, dependabotToken, "", "dependabot registry request")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.deltaforce.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce registry request")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://example.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "deltaforce registry request")

	// Path mismatch
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://corp.dependabot.com/foo", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "dependabot registry request")

	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pypy.com/other/pgk/a", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "other registry request")

	// Path mismatch on /+simple
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pypy.com/dependabot/pgk/a", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "dependabot", "sec123", "dependabot pypy registry request")

	// Path mismatch on /simple
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pypy.com/simple/pgk/a", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, "simple", "sec245", "simple pypy registry request")

	// Missing repo subdomain
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://dependabot.com/pyreg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "different subdomain")

	// HTTP, not HTTPS
	req = httptest.NewRequestWithContext(t.Context(), "GET", "http://corp.dependabot.com/pyreg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "http, not https")

	// Not a GET request
	req = httptest.NewRequestWithContext(t.Context(), "POST", "https://corp.dependabot.com/pyreg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertUnauthenticated(t, req, "post request")

	// Azure DevOps
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.dev.azure.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "azure devops registry request")

	// Azure DevOps case insensitive
	req = httptest.NewRequestWithContext(t.Context(), "GET", "https://PKGS.dev.azure.com/somepkg", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "azure devops case insensitive registry request")

	// Package download on completely different path on same host
	// Simulates: config pypi.cyco.fun/pypi, but request to pypi.cyco.fun/packages/...
	// Using corp.deltaforce.com which has / as the index path
	req = httptest.NewRequest("GET", "https://corp.deltaforce.com/packages/somepkg/1.0/wheel.whl", nil)
	req = handleRequestAndClose(handler, req, nil)
	assertHasBasicAuth(t, req, deltaForceUser, deltaForcePassword, "cert registry with package download on different path")
}

func TestPythonIndexHandlerAuthenticatesDiscoveredDownloadPrefixFromHTML(t *testing.T) {
	handler := NewPythonIndexHandler(config.Credentials{
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pkgs.example.com/my-org/my-project/_packaging/my-feed/pypi/simple/",
			"token":     "user:pass",
		},
	})

	proxyCtx := &goproxy.ProxyCtx{}
	indexReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com/my-org/my-project/_packaging/my-feed/pypi/simple/my-package/",
		nil)

	indexReq = handleRequestAndClose(handler, indexReq, proxyCtx)
	assertHasBasicAuth(t, indexReq, "user", "pass", "simple index request")

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
				<a href="https://pkgs.example.com/other-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl">
					other-org file
				</a>
			</body></html>
		`)),
	}
	handler.HandleResponse(indexResp, proxyCtx)

	downloadReq := httptest.NewRequestWithContext(t.Context(),
		"HEAD",
		"https://pkgs.example.com/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		nil)

	downloadReq = handleRequestAndClose(handler, downloadReq, &goproxy.ProxyCtx{})
	assertHasBasicAuth(t, downloadReq, "user", "pass", "discovered download request")

	samePrefixReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com/my-org/project-id/_packaging/feed-id/pypi/download/another-package/2.0.0/another-package-2.0.0.whl",
		nil)

	samePrefixReq = handleRequestAndClose(handler, samePrefixReq, &goproxy.ProxyCtx{})
	assertHasBasicAuth(t, samePrefixReq, "user", "pass", "same discovered download prefix request")

	otherOrgReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com/other-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		nil)

	otherOrgReq = handleRequestAndClose(handler, otherOrgReq, &goproxy.ProxyCtx{})
	assertUnauthenticated(t, otherOrgReq, "download request outside authenticated path scope")
}

func TestPythonIndexHandlerAuthenticatesDiscoveredDownloadPrefixFromJSON(t *testing.T) {
	handler := NewPythonIndexHandler(config.Credentials{
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pkgs.example.com/my-org/my-project/_packaging/my-feed/pypi/simple/",
			"token":     "user:pass",
		},
	})

	proxyCtx := &goproxy.ProxyCtx{}
	indexReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com/my-org/my-project/_packaging/my-feed/pypi/simple/my-package/",
		nil)

	indexReq = handleRequestAndClose(handler, indexReq, proxyCtx)
	assertHasBasicAuth(t, indexReq, "user", "pass", "simple index request")

	indexResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.pypi.simple.v1+json"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"meta": {"api-version": "1.4"},
			"name": "my-package",
			"files": [
				{"filename": "my-package-1.0.0.whl", "url": "/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl#sha256=abc"}
			]
		}`)),
	}
	handler.HandleResponse(indexResp, proxyCtx)

	downloadReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		nil)

	downloadReq = handleRequestAndClose(handler, downloadReq, &goproxy.ProxyCtx{})
	assertHasBasicAuth(t, downloadReq, "user", "pass", "discovered JSON download request")
}

func TestPythonDownloadPrefixFromSimpleLinkRejectsUnscopedLinks(t *testing.T) {
	baseURL, err := url.Parse("https://pkgs.example.com/my-org/my-project/_packaging/my-feed/pypi/simple/my-package/")
	require.NoError(t, err)

	tests := []struct {
		name string
		link string
	}{
		{
			name: "non-HTTPS",
			link: "http://pkgs.example.com/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		},
		{
			name: "different host",
			link: "https://files.example.com/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		},
		{
			name: "different port",
			link: "https://pkgs.example.com:8443/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		},
		{
			name: "different first path segment",
			link: "https://pkgs.example.com/other-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, ok := pythonDownloadPrefixFromSimpleLink(tt.link, baseURL)
			assert.False(t, ok)
			assert.Nil(t, prefix)
		})
	}
}

func TestPythonIndexHandlerSkipsDiscoveryForAuthenticatedNonSimpleResponse(t *testing.T) {
	handler := NewPythonIndexHandler(config.Credentials{
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pkgs.example.com/org/project/",
			"token":     "user:pass",
		},
	})

	proxyCtx := &goproxy.ProxyCtx{}
	nonSimpleReq := httptest.NewRequestWithContext(t.Context(), "GET", "https://pkgs.example.com/org/project/status", nil)
	nonSimpleReq = handleRequestAndClose(handler, nonSimpleReq, proxyCtx)
	assertHasBasicAuth(t, nonSimpleReq, "user", "pass", "path-scoped python index request")

	indexResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
		Body: io.NopCloser(strings.NewReader(`
			<a href="https://pkgs.example.com/org/other-project/_packaging/feed/pypi/download/my-package/1.0.0/my-package-1.0.0.whl">
				my-package-1.0.0.whl
			</a>
		`)),
	}
	handler.HandleResponse(indexResp, proxyCtx)

	downloadReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com/org/other-project/_packaging/feed/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		nil)

	downloadReq = handleRequestAndClose(handler, downloadReq, &goproxy.ProxyCtx{})
	assertUnauthenticated(t, downloadReq, "non-Simple response should not be used for discovery")
}

func TestPythonIndexHandlerPreservesDiscoveredDownloadPrefixPort(t *testing.T) {
	handler := NewPythonIndexHandler(config.Credentials{
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pkgs.example.com:8443/my-org/my-project/_packaging/my-feed/pypi/simple/",
			"token":     "user:pass",
		},
	})

	proxyCtx := &goproxy.ProxyCtx{}
	indexReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com:8443/my-org/my-project/_packaging/my-feed/pypi/simple/my-package/",
		nil)

	indexReq = handleRequestAndClose(handler, indexReq, proxyCtx)
	assertHasBasicAuth(t, indexReq, "user", "pass", "simple index request")

	indexResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
		Body: io.NopCloser(strings.NewReader(`
			<a href="https://pkgs.example.com:8443/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl">
				my-package-1.0.0.whl
			</a>
		`)),
	}
	handler.HandleResponse(indexResp, proxyCtx)

	downloadReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com:8443/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		nil)

	downloadReq = handleRequestAndClose(handler, downloadReq, &goproxy.ProxyCtx{})
	assertHasBasicAuth(t, downloadReq, "user", "pass", "discovered download request on custom port")

	defaultPortReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		nil)

	defaultPortReq = handleRequestAndClose(handler, defaultPortReq, &goproxy.ProxyCtx{})
	assertUnauthenticated(t, defaultPortReq, "download request on default port should not match custom port prefix")
}

func TestPythonIndexHandlerPreservesDiscoveredDownloadPrefixIPv6Host(t *testing.T) {
	handler := NewPythonIndexHandler(config.Credentials{
		config.Credential{
			"type":      "python_index",
			"index-url": "https://[2001:db8::1]/my-org/my-project/_packaging/my-feed/pypi/simple/",
			"token":     "user:pass",
		},
	})

	proxyCtx := &goproxy.ProxyCtx{}
	indexReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://[2001:db8::1]/my-org/my-project/_packaging/my-feed/pypi/simple/my-package/",
		nil)

	indexReq = handleRequestAndClose(handler, indexReq, proxyCtx)
	assertHasBasicAuth(t, indexReq, "user", "pass", "simple index request")

	indexResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
		Body: io.NopCloser(strings.NewReader(`
			<a href="https://[2001:db8::1]/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl">
				my-package-1.0.0.whl
			</a>
		`)),
	}
	handler.HandleResponse(indexResp, proxyCtx)

	downloadReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://[2001:db8::1]/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl",
		nil)

	downloadReq = handleRequestAndClose(handler, downloadReq, &goproxy.ProxyCtx{})
	assertHasBasicAuth(t, downloadReq, "user", "pass", "discovered download request on IPv6 host")
}

func TestPythonIndexDownloadAuthStoreEvictsOldestEntryAtLimit(t *testing.T) {
	store := newPythonIndexDownloadAuthStore()
	auth := pythonIndexAuth{
		basic:    pythonIndexCredentials{token: "user:pass"},
		hasBasic: true,
	}

	for i := range maxPythonIndexDownloadAuthEntries + 1 {
		prefix, err := url.Parse(fmt.Sprintf(
			"https://pkgs.example.com/org/project/_packaging/feed-%d/pypi/download/",
			i,
		))
		require.NoError(t, err)
		store.add(prefix, auth)
	}

	store.mutex.RLock()
	entryCount := len(store.entries)
	store.mutex.RUnlock()
	assert.Equal(t, maxPythonIndexDownloadAuthEntries, entryCount)

	evictedReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com/org/project/_packaging/feed-0/pypi/download/pkg/1.0/pkg.whl",
		nil)

	evictedAuth, ok := store.authFor(evictedReq)
	assert.False(t, ok)
	assert.Zero(t, evictedAuth)

	retainedReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		fmt.Sprintf(
			"https://pkgs.example.com/org/project/_packaging/feed-%d/pypi/download/pkg/1.0/pkg.whl",
			maxPythonIndexDownloadAuthEntries,
		),
		nil)

	_, ok = store.authFor(retainedReq)
	assert.True(t, ok)
}

func TestPythonIndexHandlerSkipsDiscoveryForLargeSimpleResponse(t *testing.T) {
	handler := NewPythonIndexHandler(config.Credentials{
		config.Credential{
			"type":      "python_index",
			"index-url": "https://pkgs.example.com/my-org/my-project/_packaging/my-feed/pypi/simple/",
			"token":     "user:pass",
		},
	})

	proxyCtx := &goproxy.ProxyCtx{}
	indexReq := httptest.NewRequestWithContext(t.Context(),
		"GET",
		"https://pkgs.example.com/my-org/my-project/_packaging/my-feed/pypi/simple/my-package/",
		nil)

	indexReq = handleRequestAndClose(handler, indexReq, proxyCtx)
	assertHasBasicAuth(t, indexReq, "user", "pass", "simple index request")

	downloadURL := "https://pkgs.example.com/my-org/project-id/_packaging/feed-id/pypi/download/my-package/1.0.0/my-package-1.0.0.whl"
	responseBody := `<a href="` + downloadURL + `">file</a>` + strings.Repeat("x", maxPythonIndexDiscoveryBytes)
	indexResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
		Body: io.NopCloser(strings.NewReader(responseBody)),
	}
	handler.HandleResponse(indexResp, proxyCtx)

	replayedBody, err := io.ReadAll(indexResp.Body)
	require.NoError(t, err)
	assert.Equal(t, responseBody, string(replayedBody))

	downloadReq := httptest.NewRequestWithContext(t.Context(), "GET", downloadURL, nil)
	downloadReq = handleRequestAndClose(handler, downloadReq, &goproxy.ProxyCtx{})
	assertUnauthenticated(t, downloadReq, "large Simple API response should not be used for discovery")
}
