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
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/dependabot/proxy/internal/config"
)

var (
	iPV4Localhost   = net.ParseIP("127.0.0.1")
	iPV6Localhost   = net.ParseIP("::1")
	testProxyConfig = &config.Config{
		CA: testCA(),
	}
)

func TestProxyHTTPRequest(t *testing.T) {
	var blockedIPs []net.IP
	client, proxy := testProxyServer(t, testProxyConfig, blockedIPs)
	defer proxy.Close()

	url, httpSrv := testHTTPServer(t)
	defer httpSrv.Close()

	rsp, err := client.Get(url)
	if err != nil {
		t.Errorf("making proxied request: %v", err)
	}
	defer rsp.Body.Close()
	assert.Equal(t, 200, rsp.StatusCode)
}

// TestProxyMITMNegotiatesH2 verifies that the proxy's MITM TLS advertises h2
// via ALPN so HTTP/2 clients (such as cargo's sparse crates.io index client)
// can negotiate h2 through the proxy. Without this, libcurl returns
// "[8] Weird server reply (Invalid status line)" when it sends an HTTP/2
// client preface and the proxy closes the connection.
func TestProxyMITMNegotiatesH2(t *testing.T) {
	var blockedIPs []net.IP
	_, proxySrv := testProxyServer(t, testProxyConfig, blockedIPs)
	defer proxySrv.Close()

	conn, err := net.DialTimeout("tcp", proxySrv.Addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT request for an arbitrary HTTPS host
	connectReq := "CONNECT index.crates.io:443 HTTP/1.1\r\nHost: index.crates.io:443\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	// Read CONNECT response (byte-by-byte to avoid consuming TLS data)
	connectResp := make([]byte, 0, 64)
	oneByte := make([]byte, 1)
	for !bytes.HasSuffix(connectResp, []byte("\r\n\r\n")) {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(oneByte); err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		connectResp = append(connectResp, oneByte[0])
	}
	assert.Contains(t, string(connectResp), "200")

	// Perform TLS handshake with h2 in ALPN NextProtos
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM([]byte(testProxyConfig.CA.Cert))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: "index.crates.io",
		RootCAs:    rootCAs,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	defer tlsConn.Close()

	tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// The proxy MITM TLS must have negotiated h2
	assert.Equal(t, "h2", tlsConn.ConnectionState().NegotiatedProtocol,
		"proxy MITM TLS should negotiate h2 when requested via ALPN")
}

func TestIPRestrictions(t *testing.T) {
	blockedIPs = []net.IP{iPV4Localhost, iPV6Localhost}
	client, proxy := testProxyServer(t, testProxyConfig, blockedIPs)
	defer proxy.Close()

	_, httpSrv := testHTTPServer(t)
	defer httpSrv.Close()

	httpTestCases := []string{
		"http://127.0.0.1",
		"http://127.0.0.1/?q=query",
		"http://localhost",
		"http://localhost/path/to/endpoint",
		"http://[::1]/",
	}

	for _, url := range httpTestCases {
		t.Run(url, func(t *testing.T) {
			rsp, err := client.Get(url)
			if err != nil {
				t.Errorf("making proxied request: %v", err)
				return
			}
			defer rsp.Body.Close()

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
			_, err := client.Get(url) //nolint:bodyclose // error expected, no body to close
			assert.Error(t, err)
		})
	}
}

func TestMetadataAPIRestriction(t *testing.T) {
	var blockedIPs []net.IP
	client, proxy := testProxyServer(t, testProxyConfig, blockedIPs)
	defer proxy.Close()

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
			if err != nil {
				t.Errorf("initializing new request: %v", err)
			}
			req.Host = tc.host

			rsp, err := client.Do(req)
			if err != nil {
				t.Errorf("making proxied request: %v", err)
			}
			defer rsp.Body.Close()

			assert.Equal(t, 403, rsp.StatusCode)
		})
	}
}

func testProxyServer(t *testing.T, cfg *config.Config, blockedIPs []net.IP) (*http.Client, *http.Server) {
	envSettings := config.ProxyEnvSettings{
		APIEndpoint:    "",
		PackageManager: "",
		GroupedUpdate:  "",
		JobID:          "",
		JobToken:       "",
	}

	// Spin up a test proxy server
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
	}
	srv.Handler = newProxy(envSettings, testProxyConfig, blockedIPs)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Errorf("net.Listen: %v", err)
	}
	srv.Addr = ln.Addr().String()

	go func() {
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			t.Errorf("ListenAndServe: %v", err)
		}
	}()

	// Build a client for the proxy
	proxyURL, err := url.Parse("http://" + srv.Addr)
	if err != nil {
		t.Errorf("url.Parse: %v", err)
	}
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM([]byte(testProxyConfig.CA.Cert)); !ok {
		t.Fatal("AppendCertsFromPEM not ok")
	}
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
	if err != nil {
		t.Errorf("net.Listen: %v", err)
	}
	srv.Addr = ln.Addr().String()

	go func() {
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			t.Errorf("ListenAndServe: %v", err)
		}
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
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	return config.CaDetails{
		Cert: caPEM.String(),
		Key:  caPrivKeyPEM.String(),
	}
}
