package helpers

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// newRequest builds a GET request to the given raw URL for use in tests.
func newRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	return httptest.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
}

// newRequestWithAuth builds a request that already carries an Authorization header,
// simulating a client that sent credentials which should be replaced.
func newRequestWithAuth(t *testing.T, rawURL, existing string) *http.Request {
	t.Helper()
	req := newRequest(t, rawURL)
	req.Header.Set("Authorization", existing)
	return req
}

func TestSetBasicAuthorization(t *testing.T) {
	t.Run("sets correct Basic header", func(t *testing.T) {
		req := newRequest(t, "https://example.com")
		SetBasicAuthorization(req, "user", "pass")

		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
		assert.Equal(t, want, req.Header.Get("Authorization"))
	})

	t.Run("clears pre-existing Authorization header", func(t *testing.T) {
		req := newRequestWithAuth(t, "https://example.com", "Bearer old-token")
		SetBasicAuthorization(req, "user", "pass")

		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
		assert.Equal(t, want, req.Header.Get("Authorization"))
		assert.Len(t, req.Header["Authorization"], 1)
	})

	t.Run("encodes empty username correctly", func(t *testing.T) {
		req := newRequest(t, "https://example.com")
		SetBasicAuthorization(req, "", "token")

		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(":token"))
		assert.Equal(t, want, req.Header.Get("Authorization"))
	})
}

func TestSetBearerAuthorization(t *testing.T) {
	t.Run("sets correct Bearer header", func(t *testing.T) {
		req := newRequest(t, "https://example.com")
		SetBearerAuthorization(req, "my-token")

		assert.Equal(t, "Bearer my-token", req.Header.Get("Authorization"))
	})

	t.Run("clears pre-existing Authorization header", func(t *testing.T) {
		req := newRequestWithAuth(t, "https://example.com", "Basic dXNlcjpwYXNz")
		SetBearerAuthorization(req, "new-token")

		assert.Equal(t, "Bearer new-token", req.Header.Get("Authorization"))
		assert.Len(t, req.Header["Authorization"], 1)
	})
}

func TestSetGitHubAPITokenAuthorization(t *testing.T) {
	t.Run("sets correct token header", func(t *testing.T) {
		req := newRequest(t, "https://api.github.com")
		SetGitHubAPITokenAuthorization(req, "ghp_abc123")

		assert.Equal(t, "token ghp_abc123", req.Header.Get("Authorization"))
	})

	t.Run("clears pre-existing Authorization header", func(t *testing.T) {
		req := newRequestWithAuth(t, "https://api.github.com", "token old-token")
		SetGitHubAPITokenAuthorization(req, "new-token")

		assert.Equal(t, "token new-token", req.Header.Get("Authorization"))
		assert.Len(t, req.Header["Authorization"], 1)
	})
}

func TestSetRawAuthorization(t *testing.T) {
	t.Run("sets pre-formatted value as-is", func(t *testing.T) {
		req := newRequest(t, "https://example.com")
		SetRawAuthorization(req, "Bearer already-formatted")

		assert.Equal(t, "Bearer already-formatted", req.Header.Get("Authorization"))
	})

	t.Run("clears pre-existing Authorization header", func(t *testing.T) {
		req := newRequestWithAuth(t, "https://example.com", "Bearer stale")
		SetRawAuthorization(req, "token new-raw")

		assert.Equal(t, "token new-raw", req.Header.Get("Authorization"))
		assert.Len(t, req.Header["Authorization"], 1)
	})
}

func TestReplaceAuthorization_CustomKey(t *testing.T) {
	t.Run("sets value on custom header key", func(t *testing.T) {
		req := newRequest(t, "https://cloudsmith.example.com")
		ReplaceAuthorization(req, "X-Api-Key", "my-api-key")

		assert.Equal(t, "my-api-key", req.Header.Get("X-Api-Key"))
		assert.Empty(t, req.Header.Get("Authorization"))
	})

	t.Run("clears pre-existing Authorization header before setting custom key", func(t *testing.T) {
		req := newRequest(t, "https://cloudsmith.example.com")
		req.Header.Set("X-Api-Key", "old-key")
		ReplaceAuthorization(req, "X-Api-Key", "new-key")

		assert.Equal(t, "new-key", req.Header.Get("X-Api-Key"))
		assert.Len(t, req.Header["X-Api-Key"], 1)
	})
}

func TestHostMatchesDomain(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		domain string
		want   bool
	}{
		{"exact match", "npmjs.org", "npmjs.org", true},
		{"subdomain match", "registry.npmjs.org", "npmjs.org", true},
		{"nested subdomain match", "a.b.npmjs.org", "npmjs.org", true},
		{"case insensitive", "REGISTRY.NPMJS.ORG", "npmjs.org", true},
		{"trailing dot on host", "registry.npmjs.org.", "npmjs.org", true},
		{"trailing dot on domain", "registry.npmjs.org", "npmjs.org.", true},
		{"label-boundary guard", "evilnpmjs.org", "npmjs.org", false},
		{"suffix in the middle", "npmjs.org.evil.com", "npmjs.org", false},
		{"unrelated host", "example.com", "npmjs.org", false},
		{"empty host", "", "npmjs.org", false},
		{"empty domain", "npmjs.org", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, HostMatchesDomain(tc.host, tc.domain))
		})
	}
}

func TestUrlMatchesRequest(t *testing.T) {
	tests := []struct {
		name      string
		reqURL    string
		urlStr    string
		pathMatch bool
		expected  bool
	}{
		{
			name:      "Matching host and port with pathMatch false",
			reqURL:    "https://example.com:443/some/path",
			urlStr:    "https://example.com:443/another/path",
			pathMatch: false,
			expected:  true,
		},
		{
			name:      "Matching host and port with pathMatch true",
			reqURL:    "https://example.com:443/some/path",
			urlStr:    "https://example.com:443/some",
			pathMatch: true,
			expected:  true,
		},
		{
			name:      "Non-matching host",
			reqURL:    "https://example.com:443/some/path",
			urlStr:    "https://another.com:443/some/path",
			pathMatch: false,
			expected:  false,
		},
		{
			name:      "Non-matching port",
			reqURL:    "https://example.com:443/some/path",
			urlStr:    "https://example.com:80/some/path",
			pathMatch: false,
			expected:  false,
		},
		{
			name:      "Matching host but non-matching path with pathMatch true",
			reqURL:    "https://example.com:443/some/path",
			urlStr:    "https://example.com:443/another/path",
			pathMatch: true,
			expected:  false,
		},
		{
			name:      "Matching host and default port with pathMatch false",
			reqURL:    "https://example.com/some/path",
			urlStr:    "https://example.com/another/path",
			pathMatch: false,
			expected:  true,
		},
		{
			name:      "Matching host and default port with pathMatch true",
			reqURL:    "https://example.com/some/path",
			urlStr:    "https://example.com/some",
			pathMatch: true,
			expected:  true,
		},
		{
			name:      "Case insensitive host match",
			reqURL:    "https://EXAMPLE.com/some/path",
			urlStr:    "https://example.com/some/path",
			pathMatch: true,
			expected:  true,
		},
		{
			name:      "Homograph attack",
			reqURL:    "https://xn--exmple-cua.com/some/path", // punycode for exämple.com
			urlStr:    "https://example.com/some/path",
			pathMatch: true,
			expected:  false,
		},
		{
			name:      "Case-sensitive punycode",
			reqURL:    "https://éxample.com/some/path",
			urlStr:    "https://ÉXAMPLE.com/some/path",
			pathMatch: true,
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqURL, _ := url.Parse(tt.reqURL)
			req := &http.Request{URL: reqURL}

			result := UrlMatchesRequest(req, tt.urlStr, tt.pathMatch)
			assert.Equal(t, tt.expected, result)
		})
	}
}
