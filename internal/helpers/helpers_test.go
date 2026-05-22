package helpers

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// newRequest builds a GET request to the given raw URL for use in tests.
func newRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, rawURL, nil)
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
		if got := req.Header.Get("Authorization"); got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
	})

	t.Run("clears pre-existing Authorization header", func(t *testing.T) {
		req := newRequestWithAuth(t, "https://example.com", "Bearer old-token")
		SetBasicAuthorization(req, "user", "pass")

		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
		if got := req.Header.Get("Authorization"); got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		if vals := req.Header["Authorization"]; len(vals) != 1 {
			t.Errorf("expected exactly 1 Authorization value, got %d: %v", len(vals), vals)
		}
	})

	t.Run("encodes empty username correctly", func(t *testing.T) {
		req := newRequest(t, "https://example.com")
		SetBasicAuthorization(req, "", "token")

		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(":token"))
		if got := req.Header.Get("Authorization"); got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
	})
}

func TestSetBearerAuthorization(t *testing.T) {
	t.Run("sets correct Bearer header", func(t *testing.T) {
		req := newRequest(t, "https://example.com")
		SetBearerAuthorization(req, "my-token")

		if got := req.Header.Get("Authorization"); got != "Bearer my-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer my-token")
		}
	})

	t.Run("clears pre-existing Authorization header", func(t *testing.T) {
		req := newRequestWithAuth(t, "https://example.com", "Basic dXNlcjpwYXNz")
		SetBearerAuthorization(req, "new-token")

		if got := req.Header.Get("Authorization"); got != "Bearer new-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer new-token")
		}
		if vals := req.Header["Authorization"]; len(vals) != 1 {
			t.Errorf("expected exactly 1 Authorization value, got %d: %v", len(vals), vals)
		}
	})
}

func TestSetGitHubAPITokenAuthorization(t *testing.T) {
	t.Run("sets correct token header", func(t *testing.T) {
		req := newRequest(t, "https://api.github.com")
		SetGitHubAPITokenAuthorization(req, "ghp_abc123")

		if got := req.Header.Get("Authorization"); got != "token ghp_abc123" {
			t.Errorf("Authorization = %q, want %q", got, "token ghp_abc123")
		}
	})

	t.Run("clears pre-existing Authorization header", func(t *testing.T) {
		req := newRequestWithAuth(t, "https://api.github.com", "token old-token")
		SetGitHubAPITokenAuthorization(req, "new-token")

		if got := req.Header.Get("Authorization"); got != "token new-token" {
			t.Errorf("Authorization = %q, want %q", got, "token new-token")
		}
		if vals := req.Header["Authorization"]; len(vals) != 1 {
			t.Errorf("expected exactly 1 Authorization value, got %d: %v", len(vals), vals)
		}
	})
}

func TestSetRawAuthorization(t *testing.T) {
	t.Run("sets pre-formatted value as-is", func(t *testing.T) {
		req := newRequest(t, "https://example.com")
		SetRawAuthorization(req, "Bearer already-formatted")

		if got := req.Header.Get("Authorization"); got != "Bearer already-formatted" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer already-formatted")
		}
	})

	t.Run("clears pre-existing Authorization header", func(t *testing.T) {
		req := newRequestWithAuth(t, "https://example.com", "Bearer stale")
		SetRawAuthorization(req, "token new-raw")

		if got := req.Header.Get("Authorization"); got != "token new-raw" {
			t.Errorf("Authorization = %q, want %q", got, "token new-raw")
		}
		if vals := req.Header["Authorization"]; len(vals) != 1 {
			t.Errorf("expected exactly 1 Authorization value, got %d: %v", len(vals), vals)
		}
	})
}

func TestReplaceAuthorization_CustomKey(t *testing.T) {
	t.Run("sets value on custom header key", func(t *testing.T) {
		req := newRequest(t, "https://cloudsmith.example.com")
		ReplaceAuthorization(req, "X-Api-Key", "my-api-key")

		if got := req.Header.Get("X-Api-Key"); got != "my-api-key" {
			t.Errorf("X-Api-Key = %q, want %q", got, "my-api-key")
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization should be empty, got %q", got)
		}
	})

	t.Run("clears pre-existing Authorization header before setting custom key", func(t *testing.T) {
		req := newRequest(t, "https://cloudsmith.example.com")
		req.Header.Set("X-Api-Key", "old-key")
		ReplaceAuthorization(req, "X-Api-Key", "new-key")

		if got := req.Header.Get("X-Api-Key"); got != "new-key" {
			t.Errorf("X-Api-Key = %q, want %q", got, "new-key")
		}
		if vals := req.Header["X-Api-Key"]; len(vals) != 1 {
			t.Errorf("expected exactly 1 X-Api-Key value, got %d: %v", len(vals), vals)
		}
	})
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
			if result != tt.expected {
				t.Errorf("urlMatchesRequest() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
