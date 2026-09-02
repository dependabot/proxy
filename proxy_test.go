package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/testhelpers"
)

var (
	iPV4Localhost   = net.ParseIP("127.0.0.1")
	iPV6Localhost   = net.ParseIP("::1")
	testProxyConfig = &config.Config{
		CA: testCA(),
	}
)

func closeOnCleanup(t *testing.T, closer io.Closer) {
	t.Helper()
	t.Cleanup(func() {
		require.NoError(t, closer.Close())
	})
}

func TestProxyHTTPRequest(t *testing.T) {
	var blockedIPs []net.IP
	client, proxy := testProxyServer(t, testProxyConfig, blockedIPs)
	closeOnCleanup(t, proxy)

	url, httpSrv := testHTTPServer(t)
	closeOnCleanup(t, httpSrv)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	rsp, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, rsp.Body.Close())
	}()
	assert.Equal(t, 200, rsp.StatusCode)
}

func TestProxyEgressAllowlistEnforceBlocks(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		CA:              testProxyConfig.CA,
		EgressAllowlist: config.EgressAllowlist{Enforce: true},
	}
	env := config.ProxyEnvSettings{PackageManager: "npm_and_yarn"}
	client, proxy := testProxyServerWithEnv(t, env, cfg, nil, upstream.Certificate())
	closeOnCleanup(t, proxy)

	// The upstream host (127.0.0.1) is not on the allowlist, so enforce drops it.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
	require.NoError(t, err)
	rsp, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, rsp.Body.Close())
	}()
	assert.Equal(t, http.StatusForbidden, rsp.StatusCode)
}

func TestProxyEgressAllowlistObserveAllows(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		CA:              testProxyConfig.CA,
		EgressAllowlist: config.EgressAllowlist{Observe: true},
	}
	env := config.ProxyEnvSettings{PackageManager: "npm_and_yarn"}
	client, proxy := testProxyServerWithEnv(t, env, cfg, nil, upstream.Certificate())
	closeOnCleanup(t, proxy)

	// Observe mode logs the non-allowlisted host but still lets it through.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
	require.NoError(t, err)
	rsp, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, rsp.Body.Close())
	}()
	assert.Equal(t, http.StatusOK, rsp.StatusCode)
}

func TestProxyHTTPSMITMFixedLengthResponseFraming(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		_, err := io.WriteString(w, "hello")
		assert.NoError(t, err)
	}))
	defer upstream.Close()

	t.Setenv("PROXY_CACHE", "false")
	client, proxy := testProxyServer(t, testProxyConfig, nil, upstream.Certificate())
	closeOnCleanup(t, proxy)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, "hello", string(body))
	assert.Empty(t, resp.TransferEncoding)
	assert.Equal(t, int64(len(body)), resp.ContentLength)
}

// TestProxyHTTPSMITMResponseFraming drives many response shapes over a single
// reused MITM tunnel with caching enabled and then issues a follow-up request
// on the same connection. If any response mis-frames (e.g. a bodyless 204/304
// or a cache-wrapped body writing a stray chunk terminator), the follow-up
// request desyncs and fails, reproducing the keep-alive framing bug.
func TestProxyHTTPSMITMResponseFraming(t *testing.T) {
	var fixedGETRequests atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fixed":
			if r.Method == http.MethodGet {
				fixedGETRequests.Add(1)
			}
			_, err := io.WriteString(w, "hello")
			assert.NoError(t, err)
		case "/chunked":
			_, err := io.WriteString(w, "hello ")
			assert.NoError(t, err)
			w.(http.Flusher).Flush()
			_, err = io.WriteString(w, "world")
			assert.NoError(t, err)
		case "/trailers":
			w.Header().Set("Trailer", "X-Checksum")
			_, err := io.WriteString(w, "trailed")
			assert.NoError(t, err)
			w.Header().Set("X-Checksum", "abc123")
		case "/no-content":
			w.WriteHeader(http.StatusNoContent)
		case "/not-modified":
			w.WriteHeader(http.StatusNotModified)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	t.Setenv("PROXY_CACHE", "true")
	client, proxy := testProxyServer(t, testProxyConfig, nil, upstream.Certificate())
	closeOnCleanup(t, proxy)
	transport := client.Transport.(*http.Transport)
	var proxyDials atomic.Int32
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		proxyDials.Add(1)
		return dialer.DialContext(ctx, network, address)
	}

	tests := []struct {
		name       string
		method     string
		path       string
		statusCode int
		body       string
		chunked    bool
		trailer    string
	}{
		{name: "cache-wrapped fixed body", method: http.MethodGet, path: "/fixed", statusCode: http.StatusOK, body: "hello", chunked: true},
		{name: "unknown length", method: http.MethodGet, path: "/chunked", statusCode: http.StatusOK, body: "hello world", chunked: true},
		{name: "trailers", method: http.MethodGet, path: "/trailers", statusCode: http.StatusOK, body: "trailed", chunked: true, trailer: "abc123"},
		{name: "HEAD", method: http.MethodHead, path: "/fixed", statusCode: http.StatusOK},
		{name: "no content", method: http.MethodGet, path: "/no-content", statusCode: http.StatusNoContent},
		{name: "not modified", method: http.MethodGet, path: "/not-modified", statusCode: http.StatusNotModified},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), test.method, upstream.URL+test.path, nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			assert.Equal(t, test.statusCode, resp.StatusCode)
			assert.Equal(t, test.body, string(body))
			if test.chunked {
				assert.Equal(t, []string{"chunked"}, resp.TransferEncoding)
			}
			if test.trailer != "" {
				assert.Equal(t, test.trailer, resp.Trailer.Get("X-Checksum"))
			}

			// Follow-up request on the SAME reused tunnel. If the previous
			// response desynced the connection this read fails.
			req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/fixed", nil)
			require.NoError(t, err)
			resp, err = client.Do(req)
			require.NoError(t, err)
			body, err = io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, "hello", string(body))
		})
	}
	// The first /fixed GET is served from upstream; every later /fixed GET is a
	// cache hit, and the whole suite reuses one proxy tunnel.
	require.Equal(t, int32(1), fixedGETRequests.Load())
	require.Equal(t, int32(1), proxyDials.Load())
}

// TestProxyHTTPSMITMHeadCacheHitPreservesContentLength verifies that a HEAD
// response served from the cache advertises the same Content-Length as the
// original upstream response instead of reporting zero, while still sending no
// body and not desyncing the reused tunnel.
func TestProxyHTTPSMITMHeadCacheHitPreservesContentLength(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, err := io.WriteString(w, "hello")
		assert.NoError(t, err)
	}))
	defer upstream.Close()

	t.Setenv("PROXY_CACHE", "true")
	client, proxy := testProxyServer(t, testProxyConfig, nil, upstream.Certificate())
	closeOnCleanup(t, proxy)
	transport := client.Transport.(*http.Transport)
	var proxyDials atomic.Int32
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		proxyDials.Add(1)
		return dialer.DialContext(ctx, network, address)
	}

	// First HEAD is a cache miss served from upstream; the second is a cache
	// hit served by the proxy. Both must report Content-Length: 5.
	for i := 0; i < 2; i++ {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodHead, upstream.URL+"/fixed", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, body, "HEAD response must have no body")
		assert.Equal(t, int64(5), resp.ContentLength, "HEAD must advertise the resource length on both miss and hit")
	}

	require.Equal(t, int32(1), upstreamHits.Load(), "second HEAD must be served from cache")
	require.Equal(t, int32(1), proxyDials.Load(), "both requests must reuse one tunnel")
}

// TestProxyHTTPSConditionalNotModifiedPreservesCachedResponse verifies that a
// 304 response served through the cache does not corrupt the tunnel, and that a
// later unconditional request still returns the original cached 200 body.
func TestProxyHTTPSConditionalNotModifiedPreservesCachedResponse(t *testing.T) {
	const (
		etag = `"v1"`
		body = "cached response"
	)
	var upstreamRequests atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, err := io.WriteString(w, body)
		assert.NoError(t, err)
	}))
	defer upstream.Close()

	t.Setenv("PROXY_CACHE", "true")
	client, proxy := testProxyServer(t, testProxyConfig, nil, upstream.Certificate())
	closeOnCleanup(t, proxy)
	transport := client.Transport.(*http.Transport)
	var proxyDials atomic.Int32
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		proxyDials.Add(1)
		return dialer.DialContext(ctx, network, address)
	}

	request := func(ifNoneMatch string) *http.Response {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
		require.NoError(t, err)
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	resp := request("")
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, body, string(responseBody))

	resp = request(etag)
	responseBody, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNotModified, resp.StatusCode)
	assert.Empty(t, responseBody)

	resp = request("")
	responseBody, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, body, string(responseBody))
	assert.Equal(t, etag, resp.Header.Get("ETag"))

	assert.Equal(t, int32(2), upstreamRequests.Load())
	assert.Equal(t, int32(1), proxyDials.Load())
}

// TestProxyUpstreamCloseIsNotCachedAsBodylessResponse verifies that an upstream
// connection failure (goproxy returns no response, synthesizes a 500) is logged
// distinctly and NOT cached as if it were a valid bodyless response, so a later
// identical request can still succeed.
func TestProxyUpstreamCloseIsNotCachedAsBodylessResponse(t *testing.T) {
	var logOutput bytes.Buffer
	testhelpers.CaptureGlobalLogs(t, &logOutput)

	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if upstreamRequests.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			require.NoError(t, err)
			require.NoError(t, conn.Close())
			return
		}
		_, err := io.WriteString(w, "recovered")
		assert.NoError(t, err)
	}))
	defer upstream.Close()

	t.Setenv("PROXY_CACHE", "true")
	client, proxy := testProxyServer(t, testProxyConfig, nil)
	closeOnCleanup(t, proxy)

	request := func() *http.Response {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	resp := request()
	_, err := io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	for range 2 {
		resp = request()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "recovered", string(body))
	}

	assert.Equal(t, int32(2), upstreamRequests.Load())
	assert.Contains(t, logOutput.String(), "Received nil response")
}

func TestIPRestrictions(t *testing.T) {
	blockedIPs = []net.IP{iPV4Localhost, iPV6Localhost}
	client, proxy := testProxyServer(t, testProxyConfig, blockedIPs)
	closeOnCleanup(t, proxy)

	_, httpSrv := testHTTPServer(t)
	closeOnCleanup(t, httpSrv)

	httpTestCases := []string{
		"http://127.0.0.1",
		"http://127.0.0.1/?q=query",
		"http://localhost",
		"http://localhost/path/to/endpoint",
		"http://[::1]/",
	}

	for _, url := range httpTestCases {
		t.Run(url, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
			require.NoError(t, err)
			rsp, err := client.Do(req)
			require.NoError(t, err)
			defer func() {
				require.NoError(t, rsp.Body.Close())
			}()

			assert.Equal(t, 403, rsp.StatusCode)
		})
	}

	httpsTestCases := []string{
		"https://127.0.0.1",
		"https://127.0.0.1/?q=query",
		"https://localhost",
		"https://localhost/path/to/endpoint",
		"https://[::1]/",
	}

	// This will only happen on https request that we intentionally block. We stop
	// the connection from being established while goproxy tries to setup TLS
	for _, url := range httpsTestCases {
		t.Run(url, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
			require.NoError(t, err)
			_, err = client.Do(req) //nolint:bodyclose // error expected, no body to close
			assert.Error(t, err)
		})
	}
}

func TestMetadataAPIRestriction(t *testing.T) {
	var blockedIPs []net.IP
	client, proxy := testProxyServer(t, testProxyConfig, blockedIPs)
	closeOnCleanup(t, proxy)

	type testCase struct {
		url  string
		host string
	}

	testCases := []testCase{
		{
			url:  "http://metadata.google.internal",
			host: "metadata.google.internal",
		},
		{
			url:  "https://metadata.google.internal",
			host: "metadata.google.internal",
		},
		{
			url:  "http://metadata.google.internal/computeMetadata/v1/instance/zone",
			host: "",
		},
		{
			url:  "http://METADATA.google.internal",
			host: "",
		},
		{
			url:  "http://www.example.com",
			host: "METADATA.google.internal",
		},
		{
			url:  "http://127.0.0.1:0/path",
			host: "metadata.google.internal",
		},
		{
			url:  "https://127.0.0.1:0/path",
			host: "metadata.google.internal",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.url, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), "GET", tc.url, nil)
			require.NoError(t, err)
			req.Host = tc.host

			rsp, err := client.Do(req)
			require.NoError(t, err)
			defer func() {
				require.NoError(t, rsp.Body.Close())
			}()

			assert.Equal(t, 403, rsp.StatusCode)
		})
	}
}

func testProxyServer(t *testing.T, cfg *config.Config, blockedIPs []net.IP, upstreamRoots ...*x509.Certificate) (*http.Client, *http.Server) {
	envSettings := config.ProxyEnvSettings{
		APIEndpoint:    "",
		PackageManager: "",
		GroupedUpdate:  "",
		JobID:          "",
		JobToken:       "",
	}
	return testProxyServerWithEnv(t, envSettings, cfg, blockedIPs, upstreamRoots...)
}

func testProxyServerWithEnv(t *testing.T, envSettings config.ProxyEnvSettings, cfg *config.Config, blockedIPs []net.IP, upstreamRoots ...*x509.Certificate) (*http.Client, *http.Server) {
	// Spin up a test proxy server
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
	}
	proxyHandler := newProxyWithCacheDir(envSettings, cfg, blockedIPs, t.TempDir())
	if len(upstreamRoots) > 0 {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			rootCAs = x509.NewCertPool()
		}
		for _, certificate := range upstreamRoots {
			rootCAs.AddCert(certificate)
		}
		proxyHandler.Tr.TLSClientConfig.RootCAs = rootCAs
	}
	srv.Handler = proxyHandler

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv.Addr = ln.Addr().String()

	go func() {
		assert.ErrorIs(t, srv.Serve(ln), http.ErrServerClosed)
	}()

	// Build a client for the proxy
	proxyURL, err := url.Parse("http://" + srv.Addr)
	require.NoError(t, err)
	rootCAs := x509.NewCertPool()
	require.True(t, rootCAs.AppendCertsFromPEM([]byte(testProxyConfig.CA.Cert)))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    rootCAs,
			},
		},
	}

	return client, srv
}

func testHTTPServer(t *testing.T) (string, *http.Server) {
	// Spin up a test HTTP server
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
	}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv.Addr = ln.Addr().String()

	go func() {
		assert.ErrorIs(t, srv.Serve(ln), http.ErrServerClosed)
	}()

	return "http://" + srv.Addr, srv
}

func testCA() config.CaDetails {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Dependabot Corporation"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"GitHub HQ"},
			PostalCode:    []string{"94107"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		panic(err)
	}

	caPEM := new(bytes.Buffer)
	if err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		panic(err)
	}

	caPrivKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	}); err != nil {
		panic(err)
	}

	return config.CaDetails{
		Cert: caPEM.String(),
		Key:  caPrivKeyPEM.String(),
	}
}
