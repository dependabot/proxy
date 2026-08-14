package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// None of these tests should make network calls
const URL = "https://127.0.0.1:65535"

// closeTrackingReadCloser wraps a reader and reports when it is closed, so tests
// can assert that a replaced response body is properly closed.
type closeTrackingReadCloser struct {
	io.Reader
	onClose func()
}

func (c *closeTrackingReadCloser) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

func TestCache_Disabled(t *testing.T) {
	const enabled = false
	cacheDir := filepath.Join(os.TempDir(), strconv.Itoa(time.Now().Nanosecond()))
	defer os.RemoveAll(cacheDir)

	cacher, err := New(enabled, cacheDir)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), "GET", URL, nil)
	proxyCtx := &goproxy.ProxyCtx{
		Req: req,
	}

	// OnRequest doesn't change the request, so we don't need to check that.
	// If cached there will be a response.
	_, resp := cacher.OnRequest(req, proxyCtx)
	if resp != nil {
		resp.Body.Close()
	}
	assert.Nil(t, resp)

	// Verify that we didn't read the body of the response to cache it.
	originalBody := &BufferWithClose{}
	resp2 := &http.Response{Body: originalBody}
	proxyCtx.Resp = resp2
	resp3 := cacher.OnResponse(resp2, proxyCtx)
	defer resp3.Body.Close()
	assert.Same(t, originalBody, resp3.Body)
}

func TestCache(t *testing.T) {
	const enabled = true
	cacheDir := filepath.Join(os.TempDir(), strconv.Itoa(time.Now().Nanosecond()))
	defer os.RemoveAll(cacheDir)

	cacher, err := New(enabled, cacheDir)
	require.NoError(t, err)

	assert.Empty(t, cacher.cacheDB)

	t.Run("Cache miss", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", URL, nil)
		proxyCtx := &goproxy.ProxyCtx{
			Req: req,
		}

		_, resp := cacher.OnRequest(req, proxyCtx)
		if resp != nil {
			resp.Body.Close()
		}
		assert.Nil(t, resp)

		body := `{"hello":"world"}`
		resp = &http.Response{
			Request:    req,
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(body)),
		}
		resp = cacher.OnResponse(resp, proxyCtx)
		result, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assert.Len(t, cacher.cacheDB, 1)
		assert.Equal(t, body, string(result))
	})

	t.Run("Cache hit", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", URL, nil)
		proxyCtx := &goproxy.ProxyCtx{
			Req: req,
		}

		// a cached response means OnRequest returns a resp
		_, resp := cacher.OnRequest(req, proxyCtx)
		if assert.NotNil(t, resp) {
			resp.Body.Close()
		}

		// since the response is already cached, we don't need any other fields
		resp = &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString("")),
		}
		resp = cacher.OnResponse(resp, proxyCtx)
		resp.Body.Close()
		assert.Len(t, cacher.cacheDB, 1)
	})
}

func Test_bodyless(t *testing.T) {
	cases := []struct {
		name   string
		status int
		method string
		want   bool
	}{
		{"200 GET has body", 200, http.MethodGet, false},
		{"200 HEAD is bodyless", 200, http.MethodHead, true},
		{"100 Continue is bodyless", 100, http.MethodGet, true},
		{"101 Switching Protocols has body (upgraded stream)", 101, http.MethodGet, false},
		{"204 No Content is bodyless", 204, http.MethodGet, true},
		{"205 Reset Content is bodyless", 205, http.MethodGet, true},
		{"304 Not Modified is bodyless", 304, http.MethodGet, true},
		{"404 GET has body", 404, http.MethodGet, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, bodyless(tc.status, tc.method))
		})
	}
}

func Test_cacheableStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   bool
	}{
		{"200 OK is cacheable", 200, true},
		{"203 Non-Authoritative is cacheable", 203, true},
		{"301 Moved Permanently is cacheable", 301, true},
		{"404 Not Found is cacheable", 404, true},
		{"100 Continue is not cacheable", 100, false},
		{"204 No Content is not cacheable", 204, false},
		{"205 Reset Content is not cacheable", 205, false},
		{"304 Not Modified is not cacheable", 304, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, cacheableStatus(tc.status))
		})
	}
}

// TestCache_BodylessResponses is a regression test for the keep-alive desync
// introduced by goproxy v1.9.0. Bodyless responses (1xx/204/304/HEAD) must keep
// Body == http.NoBody through both cache paths; otherwise goproxy stamps a
// chunked terminator the client never reads, desyncing the reused MITM tunnel.
// Conditional / no-content statuses (1xx/204/205/304) are additionally never
// cached, so replaying them can't hide upstream updates; only a HEAD for a
// cacheable status is stored (headers-only).
func TestCache_BodylessResponses(t *testing.T) {
	cases := []struct {
		name              string
		method            string
		status            int
		contentLength     string
		wantCached        bool
		wantHitContentLen int64
	}{
		{"304 Not Modified", http.MethodGet, http.StatusNotModified, "", false, 0},
		{"204 No Content", http.MethodGet, http.StatusNoContent, "", false, 0},
		{"205 Reset Content", http.MethodGet, http.StatusResetContent, "", false, 0},
		{"HEAD 200", http.MethodHead, http.StatusOK, "", true, 0},
		// A HEAD advertises the length the equivalent GET would return; a cache
		// hit must report that same length, not force it to zero.
		{"HEAD 200 with Content-Length", http.MethodHead, http.StatusOK, "5", true, 5},
		// A 304 is never cached even when it carries a Content-Length.
		{"304 with Content-Length", http.MethodGet, http.StatusNotModified, "5", false, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := filepath.Join(os.TempDir(), strconv.Itoa(time.Now().Nanosecond()))
			defer os.RemoveAll(cacheDir)

			cacher, err := New(true, cacheDir)
			require.NoError(t, err)

			// --- Cache miss: OnResponse must not wrap a bodyless body. ---
			missReq := httptest.NewRequestWithContext(t.Context(), tc.method, URL, nil)
			missCtx := &goproxy.ProxyCtx{Req: missReq}
			_, resp := cacher.OnRequest(missReq, missCtx)
			require.Nil(t, resp)

			resp = &http.Response{
				Request:    missReq,
				StatusCode: tc.status,
				Header:     http.Header{},
				Body:       http.NoBody,
			}
			if tc.contentLength != "" {
				resp.Header.Set("Content-Length", tc.contentLength)
			}
			resp = cacher.OnResponse(resp, missCtx)
			assert.True(t, resp.Body == http.NoBody,
				"OnResponse must leave bodyless Body as http.NoBody (not tee-wrapped)")

			if !tc.wantCached {
				assert.Empty(t, cacher.cacheDB,
					"conditional/no-content responses must not be cached")

				// --- A later identical request must be a miss (passed through). ---
				hitReq := httptest.NewRequestWithContext(t.Context(), tc.method, URL, nil)
				hitCtx := &goproxy.ProxyCtx{Req: hitReq}
				_, hit := cacher.OnRequest(hitReq, hitCtx)
				assert.Nil(t, hit, "uncached conditional response must not produce a cache hit")
				return
			}

			assert.Len(t, cacher.cacheDB, 1, "cacheable HEAD response should be cached")

			// --- Cache hit: OnRequest must serve a bodyless response. ---
			hitReq := httptest.NewRequestWithContext(t.Context(), tc.method, URL, nil)
			hitCtx := &goproxy.ProxyCtx{Req: hitReq}
			_, hit := cacher.OnRequest(hitReq, hitCtx)
			require.NotNil(t, hit)
			assert.True(t, hit.Body == http.NoBody,
				"cache hit must serve bodyless responses with http.NoBody")
			assert.Equal(t, tc.wantHitContentLen, hit.ContentLength)
			assert.Empty(t, hit.TransferEncoding)
		})
	}
}

// TestCache_BodylessResponseWithWrappedBodyIsRestored verifies that when an
// earlier response handler has replaced a bodyless response's http.NoBody with
// another (empty) ReadCloser — as PythonIndexHandler does — OnResponse restores
// http.NoBody. Otherwise goproxy sees resp.Body != http.NoBody, stamps a chunked
// terminator, and desyncs the keep-alive MITM tunnel. This restoration happens
// whether or not the response is cached: conditional/no-content statuses are not
// cached, but their bodies must still be normalized before pass-through.
func TestCache_BodylessResponseWithWrappedBodyIsRestored(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		status     int
		wantCached bool
	}{
		{"HEAD 200", http.MethodHead, http.StatusOK, true},
		{"204 No Content", http.MethodGet, http.StatusNoContent, false},
		{"205 Reset Content", http.MethodGet, http.StatusResetContent, false},
		{"304 Not Modified", http.MethodGet, http.StatusNotModified, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := filepath.Join(os.TempDir(), strconv.Itoa(time.Now().Nanosecond()))
			defer os.RemoveAll(cacheDir)

			cacher, err := New(true, cacheDir)
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), tc.method, URL, nil)
			proxyCtx := &goproxy.ProxyCtx{Req: req}
			_, resp := cacher.OnRequest(req, proxyCtx)
			require.Nil(t, resp)

			// Simulate an upstream handler that swapped in a non-NoBody wrapper.
			closed := false
			wrapped := &closeTrackingReadCloser{Reader: bytes.NewReader(nil), onClose: func() { closed = true }}
			resp = &http.Response{
				Request:    req,
				StatusCode: tc.status,
				Header:     http.Header{},
				Body:       wrapped,
			}
			resp = cacher.OnResponse(resp, proxyCtx)

			assert.True(t, resp.Body == http.NoBody,
				"OnResponse must restore http.NoBody when a bodyless response was wrapped")
			assert.True(t, closed, "the replaced wrapper must be closed to avoid leaks")
			if tc.wantCached {
				assert.Len(t, cacher.cacheDB, 1, "cacheable HEAD response should be cached")
			} else {
				assert.Empty(t, cacher.cacheDB,
					"conditional/no-content responses must not be cached")
			}
		})
	}
}

// TestCache_SwitchingProtocolsNotCached verifies a 101 upgrade response is
// passed through untouched and never cached, so its upgraded connection stream
// (e.g. WebSocket) is not replaced with an empty body on a later request.
func TestCache_SwitchingProtocolsNotCached(t *testing.T) {
	cacheDir := filepath.Join(os.TempDir(), strconv.Itoa(time.Now().Nanosecond()))
	defer os.RemoveAll(cacheDir)

	cacher, err := New(true, cacheDir)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, URL, nil)
	proxyCtx := &goproxy.ProxyCtx{Req: req}
	_, resp := cacher.OnRequest(req, proxyCtx)
	require.Nil(t, resp)

	upgraded := io.NopCloser(bytes.NewBufferString("websocket-stream"))
	resp = &http.Response{
		Request:    req,
		StatusCode: http.StatusSwitchingProtocols,
		Body:       upgraded,
	}
	resp = cacher.OnResponse(resp, proxyCtx)
	assert.True(t, resp.Body == upgraded, "101 body must be passed through untouched")
	assert.Empty(t, cacher.cacheDB, "101 must not be cached")
}

// TestCache_ZeroByteBodyIsCached verifies a valid 200 response with an empty
// (but present) body is cached and served with a body, distinct from a bodyless
// response. It must be tee-wrapped and produce a cache entry.
func TestCache_ZeroByteBodyIsCached(t *testing.T) {
	cacheDir := filepath.Join(os.TempDir(), strconv.Itoa(time.Now().Nanosecond()))
	defer os.RemoveAll(cacheDir)

	cacher, err := New(true, cacheDir)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, URL, nil)
	proxyCtx := &goproxy.ProxyCtx{Req: req}
	_, resp := cacher.OnRequest(req, proxyCtx)
	require.Nil(t, resp)

	resp = &http.Response{
		Request:    req,
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString("")),
	}
	resp = cacher.OnResponse(resp, proxyCtx)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Empty(t, body)
	assert.Len(t, cacher.cacheDB, 1, "empty-bodied 200 should be cached")

	// Cache hit serves the stored (empty) body from file, not http.NoBody.
	hitReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, URL, nil)
	hitCtx := &goproxy.ProxyCtx{Req: hitReq}
	_, hit := cacher.OnRequest(hitReq, hitCtx)
	require.NotNil(t, hit)
	hitBody, err := io.ReadAll(hit.Body)
	require.NoError(t, err)
	require.NoError(t, hit.Body.Close())
	assert.Empty(t, hitBody)
}

// TestCache_MissingCacheFileIsNotCountedAsHit verifies that when a cache entry
// exists but its backing file is missing, OnRequest falls through to the
// upstream request without tagging it as cached or incrementing the hit
// counter, so logs and statistics stay accurate.
func TestCache_MissingCacheFileIsNotCountedAsHit(t *testing.T) {
	cacheDir := filepath.Join(os.TempDir(), strconv.Itoa(time.Now().Nanosecond()))
	defer os.RemoveAll(cacheDir)

	cacher, err := New(true, cacheDir)
	require.NoError(t, err)

	// Prime the cache with a normal bodied 200 so an entry with a file exists.
	missReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, URL, nil)
	missCtx := &goproxy.ProxyCtx{Req: missReq}
	_, resp := cacher.OnRequest(missReq, missCtx)
	require.Nil(t, resp)
	resp = &http.Response{
		Request:    missReq,
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString("hello")),
	}
	resp = cacher.OnResponse(resp, missCtx)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Len(t, cacher.cacheDB, 1)

	// Delete the backing file to simulate a missing/unreadable cache file.
	for _, entry := range cacher.cacheDB {
		require.NoError(t, os.Remove(entry.FilePath))
	}

	cachedBefore := cacher.cached
	hitReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, URL, nil)
	hitCtx := &goproxy.ProxyCtx{Req: hitReq}
	_, hit := cacher.OnRequest(hitReq, hitCtx)

	assert.Nil(t, hit, "a missing cache file must fall through to upstream")
	assert.Equal(t, cachedBefore, cacher.cached, "a missing cache file must not be counted as a hit")
	assert.False(t, WasResponseCached(hitCtx), "request must not be tagged as cached when the file is missing")
}

// TestCache_PersistedNonCacheableEntriesAreNotLoaded verifies that conditional /
// no-content entries (1xx/204/205/304) persisted in a db.yaml by an older proxy
// are dropped on load, so they are never served by OnRequest after upgrade.
func TestCache_PersistedNonCacheableEntriesAreNotLoaded(t *testing.T) {
	cacheDir := filepath.Join(os.TempDir(), strconv.Itoa(time.Now().Nanosecond()))
	require.NoError(t, os.MkdirAll(cacheDir, 0o750))
	defer os.RemoveAll(cacheDir)

	// A backing file for the cacheable (200) entry.
	bodyFile := filepath.Join(cacheDir, "000001-body")
	require.NoError(t, os.WriteFile(bodyFile, []byte("hello"), 0o600))

	persisted := []Out{
		{Key: Key{Method: http.MethodGet, URL: "https://example.test/ok"},
			Entry: &Entry{Status: http.StatusOK, FilePath: bodyFile}},
		{Key: Key{Method: http.MethodGet, URL: "https://example.test/not-modified"},
			Entry: &Entry{Status: http.StatusNotModified}},
		{Key: Key{Method: http.MethodGet, URL: "https://example.test/no-content"},
			Entry: &Entry{Status: http.StatusNoContent}},
	}
	data, err := yaml.Marshal(persisted)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "db.yaml"), data, 0o600))

	cacher, err := New(true, cacheDir)
	require.NoError(t, err)

	assert.Len(t, cacher.cacheDB, 1, "only the cacheable 200 entry should be loaded")
	_, ok := cacher.cacheDB[Key{Method: http.MethodGet, URL: "https://example.test/ok"}]
	assert.True(t, ok, "the 200 entry must be loaded")
	_, ok = cacher.cacheDB[Key{Method: http.MethodGet, URL: "https://example.test/not-modified"}]
	assert.False(t, ok, "a persisted 304 entry must not be loaded")
	_, ok = cacher.cacheDB[Key{Method: http.MethodGet, URL: "https://example.test/no-content"}]
	assert.False(t, ok, "a persisted 204 entry must not be loaded")
}

func Test_sanitize(t *testing.T) {
	var tests = []struct {
		Input, Expected string
	}{
		{"github.com", "github-com"},
		{"github../../passwd", "github------passwd"},
		{"git🥺hub!", "git-hub-"},
	}

	for _, test := range tests {
		assert.Equal(t, test.Expected, sanitize(test.Input))
	}
}

func Test_key(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://github.com", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "cli")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Custom", "One")
	req.Header.Add("Custom", "Two")

	t.Run("Reflexive property", func(t *testing.T) {
		key1 := key(req)
		key2 := key(req)
		assert.Equal(t, key1, key2)
	})

	t.Run("Methods not equal", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Method = "POST"

		key1 := key(req)
		key2 := key(req2)
		assert.NotEqual(t, key1, key2)
	})

	t.Run("URLs not equal", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.URL, _ = url.Parse("http://github.com")

		key1 := key(req)
		key2 := key(req2)
		assert.NotEqual(t, key1, key2)
	})

	t.Run("Header commutative property", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Header.Set("Custom", "Two")
		req2.Header.Add("Custom", "One")

		key1 := key(req)
		key2 := key(req2)
		assert.Equal(t, key1, key2)
	})

	t.Run("Some headers are inconsequential to the cache", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Header.Set("Connection", "Close")

		key1 := key(req)
		key2 := key(req2)
		assert.Equal(t, key1, key2)
	})

	t.Run("Headers not equal", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Header.Set("Custom", "Two")

		key1 := key(req)
		key2 := key(req2)
		assert.NotEqual(t, key1, key2)
	})

	t.Run("Body equality", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Body = io.NopCloser(bytes.NewBufferString("Hello"))
		req.Body = io.NopCloser(bytes.NewBufferString("Hello"))

		key1 := key(req)
		key2 := key(req2)
		assert.Equal(t, key1, key2)
	})

	t.Run("Body inequality", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Body = io.NopCloser(bytes.NewBufferString("Hello2"))
		req.Body = io.NopCloser(bytes.NewBufferString("Hello"))

		key1 := key(req)
		key2 := key(req2)
		assert.NotEqual(t, key1, key2)
	})

	t.Run("A request with no headers should result in a blank headerHash", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), "GET", "https://github.com", nil)
		key := key(req)
		assert.Empty(t, key.HeaderHash)
	})

	// Integration tests for the gitproto hookup. Edge-case behaviour of the
	// normalizer itself lives in internal/gitproto.
	const upUrl = "https://github.com/octocat/Hello-World.git/git-upload-pack"
	const upCT = "application/x-git-upload-pack-request"
	mkUpReq := func(url, ct, body string) *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), "POST", url, strings.NewReader(body))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		return r
	}

	t.Run("git-upload-pack: agent= drift collapses to one key", func(t *testing.T) {
		body1 := "0080want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.43.0\n" +
			"0032have 553c2077f0edc3d5dc5d17262f6aa498e69d6f8e\n0009done\n"
		body2 := "0080want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=git/2.53.0\n" +
			"0032have 553c2077f0edc3d5dc5d17262f6aa498e69d6f8e\n0009done\n"
		assert.Equal(t, key(mkUpReq(upUrl, upCT, body1)), key(mkUpReq(upUrl, upCT, body2)))
	})

	t.Run("git-upload-pack: different haves hash distinctly", func(t *testing.T) {
		body1 := "0032want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d\n0000" +
			"0032have 553c2077f0edc3d5dc5d17262f6aa498e69d6f8e\n0009done\n"
		body2 := "0032want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d\n0000" +
			"0032have a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n0009done\n"
		assert.NotEqual(t, key(mkUpReq(upUrl, upCT, body1)), key(mkUpReq(upUrl, upCT, body2)))
	})

	t.Run("git-upload-pack: malformed body falls back to raw hashing", func(t *testing.T) {
		assert.NotEqual(t, key(mkUpReq(upUrl, upCT, "garbage one")), key(mkUpReq(upUrl, upCT, "garbage two")))
	})

	t.Run("non-git POST is not normalized even with similar substrings", func(t *testing.T) {
		const u = "https://api.github.com/graphql"
		k1 := key(httptest.NewRequestWithContext(t.Context(), "POST", u, strings.NewReader(`{"q":"have stuff agent=foo"}`)))
		k2 := key(httptest.NewRequestWithContext(t.Context(), "POST", u, strings.NewReader(`{"q":"have other agent=bar"}`)))
		assert.NotEqual(t, k1, k2)
	})

	t.Run("upload-pack path without Content-Type is not normalized", func(t *testing.T) {
		const u = "https://example.com/foo/git-upload-pack"
		body1 := "0032have 553c2077f0edc3d5dc5d17262f6aa498e69d6f8e\n0009done\n"
		body2 := "0032have a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n0009done\n"
		assert.NotEqual(t, key(mkUpReq(u, "", body1)), key(mkUpReq(u, "", body2)))
	})
}

type BufferWithClose struct {
	bytes.Buffer
	WasCloseCalled bool
	ErrorToReturn  error
}

func (b *BufferWithClose) Write(p []byte) (n int, err error) {
	if b.ErrorToReturn != nil {
		return 0, b.ErrorToReturn
	}
	return b.Buffer.Write(p)
}

func (b *BufferWithClose) Close() error {
	b.WasCloseCalled = true
	return b.ErrorToReturn
}

func TestTeeReadCloser(t *testing.T) {
	t.Run("reads, writes, and calls the callback", func(t *testing.T) {
		writeCloser := &BufferWithClose{}
		readCloser := io.NopCloser(strings.NewReader("hello"))
		callbackWasCalled := false
		callback := func() {
			callbackWasCalled = true
		}
		tee := TeeReadCloser(readCloser, writeCloser, callback)

		data, err := io.ReadAll(tee)
		assert.NoError(t, err)
		assert.Equal(t, "hello", string(data))
		assert.Equal(t, "hello", writeCloser.String())
		assert.NoError(t, tee.Close())
		assert.True(t, callbackWasCalled)
		assert.True(t, writeCloser.WasCloseCalled)
	})

	t.Run("when the writer fails", func(t *testing.T) {
		writeCloser := &BufferWithClose{
			ErrorToReturn: errors.New("out of memory"),
		}
		readCloser := io.NopCloser(strings.NewReader("hello"))
		callbackWasCalled := false
		callback := func() {
			callbackWasCalled = true
		}
		tee := TeeReadCloser(readCloser, writeCloser, callback)

		data, err := io.ReadAll(tee)
		assert.NoError(t, err)
		assert.Equal(t, "hello", string(data))
		assert.NoError(t, tee.Close())
		assert.False(t, callbackWasCalled)
		assert.True(t, writeCloser.WasCloseCalled)
	})
}
