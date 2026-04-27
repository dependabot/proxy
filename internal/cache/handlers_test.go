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
)

// None of these tests should make network calls
const URL = "https://127.0.0.1:65535"

func TestCache_Disabled(t *testing.T) {
	const enabled = false
	cacheDir := filepath.Join(os.TempDir(), strconv.Itoa(time.Now().Nanosecond()))
	defer os.RemoveAll(cacheDir)

	cacher, err := New(enabled, cacheDir)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", URL, nil)
	ctx := &goproxy.ProxyCtx{
		Req: req,
	}

	// OnRequest doesn't change the request, so we don't need to check that.
	// If cached there will be a response.
	_, resp := cacher.OnRequest(req, ctx)
	if resp != nil {
		resp.Body.Close()
		t.Error("Cache is not disabled")
	}

	// Verify that we didn't read the body of the response to cache it.
	originalBody := io.NopCloser(bytes.NewBufferString(""))
	resp2 := &http.Response{Body: originalBody}
	ctx.Resp = resp2
	resp3 := cacher.OnResponse(resp2, ctx)
	defer resp3.Body.Close()
	if originalBody != resp3.Body {
		t.Error("Cache is not disabled")
	}
}

func TestCache(t *testing.T) {
	const enabled = true
	cacheDir := filepath.Join(os.TempDir(), strconv.Itoa(time.Now().Nanosecond()))
	defer os.RemoveAll(cacheDir)

	cacher, err := New(enabled, cacheDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(cacher.cacheDB) != 0 {
		t.Error("cache should have 0 entry, got", len(cacher.cacheDB))
	}

	t.Run("Cache miss", func(t *testing.T) {
		req := httptest.NewRequest("GET", URL, nil)
		ctx := &goproxy.ProxyCtx{
			Req: req,
		}

		_, resp := cacher.OnRequest(req, ctx)
		if resp != nil {
			resp.Body.Close()
			t.Error("No cache should exist yet")
		}

		body := `{"hello":"world"}`
		resp = &http.Response{
			Request:    req,
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(body)),
		}
		resp = cacher.OnResponse(resp, ctx)
		result, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(cacher.cacheDB) != 1 {
			t.Error("cache should have 1 entry, got", len(cacher.cacheDB))
		}
		if string(result) != body {
			t.Error("Data was corrupted while caching")
		}
	})

	t.Run("Cache hit", func(t *testing.T) {
		req := httptest.NewRequest("GET", URL, nil)
		ctx := &goproxy.ProxyCtx{
			Req: req,
		}

		// a cached response means OnRequest returns a resp
		_, resp := cacher.OnRequest(req, ctx)
		if resp == nil {
			t.Error("Request should be cached")
		} else {
			resp.Body.Close()
		}

		// since the response is already cached, we don't need any other fields
		resp = &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString("")),
		}
		resp = cacher.OnResponse(resp, ctx)
		resp.Body.Close()
		if len(cacher.cacheDB) != 1 {
			t.Error("cache should have 1 entry, got", len(cacher.cacheDB))
		}
	})
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
		if v := sanitize(test.Input); v != test.Expected {
			t.Errorf("sanitize %v, expected %v, got %v", test.Input, test.Expected, v)
		}
	}
}

func Test_key(t *testing.T) {
	req := httptest.NewRequest("GET", "https://github.com", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "cli")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Custom", "One")
	req.Header.Add("Custom", "Two")

	t.Run("Reflexive property", func(t *testing.T) {
		key1 := key(req)
		key2 := key(req)

		if key1 != key2 {
			t.Error("The same request should produce the same key")
		}
	})

	t.Run("Methods not equal", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Method = "POST"

		key1 := key(req)
		key2 := key(req2)
		if key2 == key1 {
			t.Error("Methods not equal")
		}
	})

	t.Run("URLs not equal", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.URL, _ = url.Parse("http://github.com")

		key1 := key(req)
		key2 := key(req2)
		if key2 == key1 {
			t.Error("URLs not equal")
		}
	})

	t.Run("Header commutative property", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Header.Set("Custom", "Two")
		req2.Header.Add("Custom", "One")

		key1 := key(req)
		key2 := key(req2)
		if key2 != key1 {
			t.Error("Header value order should not matter")
		}
	})

	t.Run("Some headers are inconsequential to the cache", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Header.Set("Connection", "Close")

		key1 := key(req)
		key2 := key(req2)
		if key2 != key1 {
			t.Error("Header should be ignored")
		}
	})

	t.Run("Headers not equal", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Header.Set("Custom", "Two")

		key1 := key(req)
		key2 := key(req2)
		if key2 == key1 {
			t.Error("Headers are not equal")
		}
	})

	t.Run("Body equality", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Body = io.NopCloser(bytes.NewBufferString("Hello"))
		req.Body = io.NopCloser(bytes.NewBufferString("Hello"))

		key1 := key(req)
		key2 := key(req2)
		if key2 != key1 {
			t.Error("Bodies are equal")
		}
	})

	t.Run("Body inequality", func(t *testing.T) {
		req2 := req.Clone(context.Background())
		req2.Body = io.NopCloser(bytes.NewBufferString("Hello2"))
		req.Body = io.NopCloser(bytes.NewBufferString("Hello"))

		key1 := key(req)
		key2 := key(req2)
		if key2 == key1 {
			t.Error("Bodies are not equal")
		}
	})

	t.Run("A request with no headers should result in a blank headerHash", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://github.com", nil)
		key := key(req)
		if key.HeaderHash != "" {
			t.Error("headerHash should be blank, got", key.HeaderHash)
		}
	})

	// Integration tests for the gitproto hookup. Edge-case behaviour of the
	// normalizer itself lives in internal/gitproto.
	const upUrl = "https://github.com/octocat/Hello-World.git/git-upload-pack"
	const upCT = "application/x-git-upload-pack-request"
	mkUpReq := func(url, ct, body string) *http.Request {
		r := httptest.NewRequest("POST", url, strings.NewReader(body))
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
		if key(mkUpReq(upUrl, upCT, body1)) != key(mkUpReq(upUrl, upCT, body2)) {
			t.Error("agent-only difference must collapse")
		}
	})

	t.Run("git-upload-pack: different haves hash distinctly", func(t *testing.T) {
		body1 := "0032want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d\n0000" +
			"0032have 553c2077f0edc3d5dc5d17262f6aa498e69d6f8e\n0009done\n"
		body2 := "0032want 7fd1a60b01f91b314f59955a4e4d4e80d8edf11d\n0000" +
			"0032have a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n0009done\n"
		if key(mkUpReq(upUrl, upCT, body1)) == key(mkUpReq(upUrl, upCT, body2)) {
			t.Error("haves shape the upstream pack and must not collapse")
		}
	})

	t.Run("git-upload-pack: malformed body falls back to raw hashing", func(t *testing.T) {
		if key(mkUpReq(upUrl, upCT, "garbage one")) == key(mkUpReq(upUrl, upCT, "garbage two")) {
			t.Error("malformed bodies must hash distinctly")
		}
	})

	t.Run("non-git POST is not normalized even with similar substrings", func(t *testing.T) {
		const u = "https://api.github.com/graphql"
		k1 := key(httptest.NewRequest("POST", u, strings.NewReader(`{"q":"have stuff agent=foo"}`)))
		k2 := key(httptest.NewRequest("POST", u, strings.NewReader(`{"q":"have other agent=bar"}`)))
		if k1 == k2 {
			t.Error("non-git POSTs must not be normalized")
		}
	})

	t.Run("upload-pack path without Content-Type is not normalized", func(t *testing.T) {
		const u = "https://example.com/foo/git-upload-pack"
		body1 := "0032have 553c2077f0edc3d5dc5d17262f6aa498e69d6f8e\n0009done\n"
		body2 := "0032have a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n0009done\n"
		if key(mkUpReq(u, "", body1)) == key(mkUpReq(u, "", body2)) {
			t.Error("missing Content-Type must skip normalization")
		}
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
		if err != nil {
			t.Error("failed to read from the tee")
		}
		if string(data) != "hello" {
			t.Error("tee did not read from the reader")
		}
		if writeCloser.String() != "hello" {
			t.Error("callback did not write to the buffer")
		}
		if err := tee.Close(); err != nil {
			t.Error("failed to close the tee")
		}
		if !callbackWasCalled {
			t.Error("callback was not called")
		}
		if !writeCloser.WasCloseCalled {
			t.Error("close was not called on the writer")
		}
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
		if err != nil {
			t.Error("the writer should not affect the reader")
		}
		if string(data) != "hello" {
			t.Error("the reader should still read from the reader")
		}
		if err := tee.Close(); err != nil {
			t.Error("failed to close the tee")
		}
		if callbackWasCalled {
			// this will prevent caching responses that failed to write to disk
			t.Error("the callback should not be called")
		}
		if !writeCloser.WasCloseCalled {
			t.Error("close was not called on the buffer")
		}
	})
}
