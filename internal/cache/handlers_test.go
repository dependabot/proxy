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
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/proxyctx"
)

// None of these tests should make network calls
const URL = "https://127.0.0.1:65535"

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

func TestCache_BodyForbiddenResponses(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		statusCode         int
		clearContentLength bool
	}{
		{name: "informational", method: http.MethodGet, statusCode: http.StatusEarlyHints},
		{name: "HEAD", method: http.MethodHead, statusCode: http.StatusOK},
		{name: "no content", method: http.MethodGet, statusCode: http.StatusNoContent},
		{name: "reset content", method: http.MethodGet, statusCode: http.StatusResetContent, clearContentLength: true},
		{name: "not modified", method: http.MethodGet, statusCode: http.StatusNotModified},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logOutput bytes.Buffer
			originalOutput := logrus.StandardLogger().Out
			logrus.SetOutput(&logOutput)
			defer logrus.SetOutput(originalOutput)

			cacher, err := New(true, t.TempDir())
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), test.method, URL, nil)
			proxyCtx := &goproxy.ProxyCtx{Req: req}
			proxyctx.SetValue(proxyCtx, keyValue, Key{Method: req.Method, URL: req.URL.String()})

			originalBody := &BufferWithClose{}
			resp := &http.Response{
				Request:          req,
				StatusCode:       test.statusCode,
				Header:           http.Header{"Content-Length": []string{"10"}, "Transfer-Encoding": []string{"chunked"}},
				Body:             originalBody,
				ContentLength:    10,
				TransferEncoding: []string{"chunked"},
			}

			result := cacher.OnResponse(resp, proxyCtx)

			assert.Same(t, resp, result)
			assert.Equal(t, http.NoBody, result.Body)
			assert.True(t, originalBody.WasCloseCalled)
			assert.Empty(t, result.TransferEncoding)
			assert.Empty(t, result.Header.Values("Transfer-Encoding"))
			if test.clearContentLength {
				assert.Zero(t, result.ContentLength)
				assert.Empty(t, result.Header.Values("Content-Length"))
			} else {
				assert.Equal(t, int64(10), result.ContentLength)
				assert.Equal(t, "10", result.Header.Get("Content-Length"))
			}
			assert.Empty(t, cacher.cacheDB)
			assert.Zero(t, cacher.callCursor)
			assert.Contains(t, logOutput.String(), "Response has no body (method: "+test.method+", status: "+strconv.Itoa(test.statusCode)+")")
		})
	}
}

func TestCache_SwitchingProtocolsPreservesUpgradedStream(t *testing.T) {
	cacher, err := New(true, t.TempDir())
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, URL, nil)
	proxyCtx := &goproxy.ProxyCtx{Req: req}
	proxyctx.SetValue(proxyCtx, keyValue, Key{Method: req.Method, URL: req.URL.String()})

	upgradedStream := &BufferWithClose{}
	resp := &http.Response{
		Request:    req,
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Upgrade": []string{"websocket"}},
		Body:       upgradedStream,
	}

	result := cacher.OnResponse(resp, proxyCtx)

	assert.Same(t, resp, result)
	assert.Same(t, upgradedStream, result.Body)
	assert.False(t, upgradedStream.WasCloseCalled)
	assert.Empty(t, cacher.cacheDB)
	assert.Zero(t, cacher.callCursor)
}

func TestCache_UnexpectedNilBodyIsNotCached(t *testing.T) {
	var logOutput bytes.Buffer
	originalOutput := logrus.StandardLogger().Out
	logrus.SetOutput(&logOutput)
	defer logrus.SetOutput(originalOutput)

	cacheDir := t.TempDir()
	cacher, err := New(true, cacheDir)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, URL, nil)
	proxyCtx := &goproxy.ProxyCtx{Req: req}
	proxyctx.SetValue(proxyCtx, keyValue, Key{Method: req.Method, URL: req.URL.String()})
	resp := &http.Response{
		Request:          req,
		StatusCode:       http.StatusOK,
		Header:           http.Header{"Content-Length": []string{"10"}, "Transfer-Encoding": []string{"chunked"}},
		ContentLength:    10,
		TransferEncoding: []string{"chunked"},
	}

	result := cacher.OnResponse(resp, proxyCtx)

	assert.Same(t, resp, result)
	assert.Equal(t, http.NoBody, result.Body)
	assert.Zero(t, result.ContentLength)
	assert.Empty(t, result.TransferEncoding)
	assert.Empty(t, result.Header.Values("Content-Length"))
	assert.Empty(t, result.Header.Values("Transfer-Encoding"))
	assert.Empty(t, cacher.cacheDB)
	assert.Zero(t, cacher.callCursor)
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
	assert.Contains(t, logOutput.String(), "Response unexpectedly has nil body (method: GET, status: 200)")
}

func TestCache_ZeroByteBodyIsCached(t *testing.T) {
	cacher, err := New(true, t.TempDir())
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, URL, nil)
	proxyCtx := &goproxy.ProxyCtx{Req: req}
	proxyctx.SetValue(proxyCtx, keyValue, Key{Method: req.Method, URL: req.URL.String()})
	resp := &http.Response{
		Request:    req,
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
	}

	result := cacher.OnResponse(resp, proxyCtx)
	_, err = io.ReadAll(result.Body)
	require.NoError(t, err)
	require.NoError(t, result.Body.Close())

	assert.Len(t, cacher.cacheDB, 1)
	assert.Equal(t, 1, cacher.callCursor)
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
