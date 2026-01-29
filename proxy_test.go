package main

import (
	"bytes"
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

	"github.com/dependabot/proxy/internal/config"
	"github.com/stretchr/testify/assert"
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
	assert.Equal(t, 200, rsp.StatusCode)
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
			_, err := client.Get(url)
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
			req, err := http.NewRequest("GET", tc.url, nil)
			if err != nil {
				t.Errorf("initializing new request: %v", err)
			}
			req.Host = tc.host

			rsp, err := client.Do(req)
			if err != nil {
				t.Errorf("making proxied request: %v", err)
			}

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
	srv := &http.Server{}
	srv.Handler = newProxy(envSettings, testProxyConfig, blockedIPs)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				RootCAs: rootCAs,
			},
		},
	}

	return client, srv
}

func testHTTPServer(t *testing.T) (string, *http.Server) {
	// Spin up a test HTTP server
	srv := &http.Server{}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
